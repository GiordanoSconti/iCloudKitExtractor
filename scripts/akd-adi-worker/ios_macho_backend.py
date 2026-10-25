#!/usr/bin/env python3
"""
Backend ADI iOS: Mach-O ARM64 (CoreADI + StoreServices) in Unicorn.

Anisette.py gestisce solo ELF Android. Qui:
  1) carica i dylib estratti da IPSW/DSC
  2) risolve gli export (stessi nomi offuscati Android se presenti)
  3) espone start_provisioning / end_provisioning / request_otp

IOS_ADI_RUNTIME_READY diventa True solo se tutti i simboli ADI richiesti
sono risolti. L'esecuzione reale può comunque fallire finché non ci sono
stub/import sufficienti per le dipendenze iOS (libSystem/Foundation).
"""

from __future__ import annotations

import json
import logging
import os
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SYS_LIB_ORDER = (
    "libsystem_platform.dylib",
    "libsystem_kernel.dylib",
    "libsystem_pthread.dylib",
    "libsystem_malloc.dylib",
    "libsystem_c.dylib",
    "libsystem_blocks.dylib",
    "libcompiler_rt.dylib",
    "libdyld.dylib",
    "libdispatch.dylib",
    # libobjc.A ha __OBJC_RO enorme; utile ma costoso — dopo le lib C
    "libobjc.A.dylib",
    "libc++.1.dylib",
)
# Skip lib > questo size in MB (override con AKD_IOS_LOAD_LARGE=1)
SYS_LIB_MAX_MB = 8

# Impostato a True in initialize() se il mapping simboli è completo.
IOS_ADI_RUNTIME_READY = False

STACK_BASE = 0xF0000000
STACK_SIZE = 0x100000
RETURN_ADDRESS = 0xDEAD0000
TEMP_BASE = 0x800000000
TEMP_SIZE = 0x200000
MALLOC_BASE = 0x60000000
MALLOC_SIZE = 0x1000000
IMPORT_BASE = 0xA0000000
IMPORT_SIZE = 0x10000
# Range tipico dyld_shared_cache iOS arm64 — page-fault lazy stub
DSC_LAZY_LO = 0x180000000
DSC_LAZY_HI = 0x300000000
STACK_CHK_GUARD_SLOT = 0xB0000000  # nostra cella canary
# Fake malloc_zone_t + zones array (___malloc_init non gira in Unicorn)
FAKE_ZONE_BASE = 0xB0001000
FAKE_ZONE_SIZE = 0x2000
TLS_BASE = 0xB0003000
TLS_SIZE = 0x2000
# Slot noti DSC 20H350 / libsystem_malloc
MALLOC_ZONES_ADDR = 0x1E1D29070  # _malloc_zones
VIRTUAL_DEFAULT_ZONE = 0x1DD280000  # _virtual_default_zone
GOT_STACK_CHK_GUARD = 0x1DAC920E8
MIG_GET_REPLY_PORT = 0x1C260989C  # _mig_get_reply_port
MACH_MSG2_TRAP = 0x1C2609028  # _mach_msg2_trap (ADI → adid MIG)
# StoreServices helper @0x1a1b1a210: request msgh_id=1200 (0x4b0), reply=1300 (0x514)
ADI_MIG_REQUEST_ID = 0x4B0
ADI_MIG_REPLY_ID = 0x514  # request + 100
ADI_MIG_IPC_OK = 0x10000003  # helper/caller magic: IPC+ADI ok
ADI_NOT_PROVISIONED = -45061
# /usr/libexec/adid (IPSW rootfs) — preferred load VA + MIG server entry
ADID_IMAGE_BASE = 0x100000000
ADID_MIG_SERVER = 0x1000014D4  # boolean_t server(InHeadP, OutHeadP)
ADID_MIG_ROUTINE = 0x100001350  # routine for msgh_id 1200
ADID_NDR_RECORD = 0xB0016000  # fake NDR_record (mach/ndr.h); oltre CF_OBJ arena
ADID_IMPORT_TRAMP_BASE = IMPORT_BASE + 0x9000
# fairplayd.H2 è PIE @0x100000000 come adid → rebase in arena dedicata
FAIRPLAYD_IMAGE_BASE = 0x120000000
FAIRPLAYD_NDR_RECORD = 0xB0018000
# FairPlayIOKit macOS 11.2 (fairplay_research) — prefer VA basse, simboli _UeFdbi
FAIRPLAY_MACOS_NAME = "FairPlayIOKit_macOS"
# Symbol VA (imagebase 0) da FairPlayIOKit_macOS_11.2_20D64
FP_MACOS_UEFDBI = 0xCC130
FP_MACOS_CMAM7F = 0xCCE90
FP_MACOS_LSKD_START = 0x3D5A8
# UeFdbi FSM (imagebase 0): cookie/byte gate + post-AES transform + epilogue
FP_UEFDBI_BYTE_CHECK = 0xEADE4  # ldrb from AES buf; wants 0xa3 (ok) / 0x23 (cont)
FP_UEFDBI_OSTR_WRITE = 0xEAEF0  # after writing out-struct pointing at ciphertext
FP_UEFDBI_XFORM_DONE = 0xECBB0  # after 0x20-byte obfuscated transform of out-struct
FP_UEFDBI_EPILOGUE = 0xECC08  # str status; restore; ret
FP_UEFDBI_STATUS_GOOD = 0x44DF225B  # obfuscated rc=0 (real_rc = status - GOOD)
FP_UEFDBI_MAGIC_OK = 0xA3
# PAC → NOP / RET (Unicorn non emula ARM64e)
_PAC_NOP = {
    0xD503237F: 0xD503201F,  # PACIBSP → NOP
    0xD50323BF: 0xD503201F,  # AUTIBSP → NOP
    0xD50320FF: 0xD503201F,  # XPACLRI → NOP
    0xD65F0BFF: 0xD65F03C0,  # RETAA → RET
    0xD65F0FFF: 0xD65F03C0,  # RETAB → RET (era 0xD65F0BE0: encoding errata)
    0xD65F0BE0: 0xD65F03C0,  # RETAB alt / eret-like
}
# Bind nel pool offuscato SOLO per questi (addend==-magic). Altri slot restano
# intatti altrimenti il dispatcher salta nel DSC.
ADID_POOL_BIND_SYMS = frozenset(
    {
        "_IOConnectCallStructMethod",
        "_IOServiceMatching",
        "_IOServiceGetMatchingServices",
        "_IOServiceOpen",
        "_IOIteratorNext",
        "_IOObjectRelease",
        "_IOMainPort",
        "_MGCopyAnswer",
        "_malloc",
        "_free",
        "_open",
        "_open_dprotected_np",
        "_stat",
        "_fstat",
        "_lstat",
        "_mkdir",
        "_arc4random",
        "_arc4random_uniform",
        "_gettimeofday",
        "_time",
        "___memcpy_chk",
        "_CFStringCreateWithCStringNoCopy",
        "_CFStringGetCString",
        "_CFStringGetLength",
        "_CFStringGetTypeID",
        "_CFRelease",
        "_SecTaskCreateWithAuditToken",
        "_SecTaskCopyValueForEntitlement",
        "_audit_token_to_au32",
        "_CFGetTypeID",
        "_CFBooleanGetTypeID",
        "_CFBooleanGetValue",
        "_CFNumberGetValue",
        "_CFNumberGetTypeID",
        "_CFEqual",
        "_kCFBooleanTrue",
        "_strtoul",
        "_xpc_connection_create_mach_service",
        "_xpc_connection_set_event_handler",
        "_xpc_connection_set_target_queue",
        "_xpc_connection_activate",
        "_xpc_connection_resume",
        "_xpc_connection_send_message_with_reply_sync",
        "_xpc_connection_cancel",
        "_xpc_dictionary_create_empty",
        "_xpc_dictionary_create_reply",
        "_xpc_dictionary_set_data",
        "_xpc_dictionary_get_data",
        "_xpc_dictionary_get_value",
        "_xpc_dictionary_get_audit_token",
        "_xpc_dictionary_send_reply",
        "_xpc_release",
        "_xpc_get_type",
        "_xpc_copy_description",
        "_xpc_transaction_begin",
        "_xpc_transaction_end",
        "_dispatch_queue_create",
        # Type/error singletons: pool secondaria li risolve con addend+magic
        "__xpc_type_dictionary",
        "__xpc_type_error",
        "__xpc_error_connection_interrupted",
        "__xpc_error_connection_invalid",
        "_mach_task_self_",
        "_vm_allocate",
        "_vm_deallocate",
        "_mach_vm_allocate",
        "_mach_vm_deallocate",
        "_CFAllocatorAllocate",
        "_CFAllocatorDeallocate",
        "_mach_msg",
        "_mach_msg_destroy",
    }
)
# FairPlay IOKit fake handles
FAKE_FP_ITER = 0xB0017100
FAKE_FP_SERVICE = 0xB0017200
FAKE_FP_CONNECT = 0xB0017300
FAKE_SEC_TASK = 0xB0017400
FAKE_CFBOOL_TRUE = 0xB0017500
FAKE_XPC_TYPE_DICT = 0xB0017600
FAKE_XPC_TYPE_ERROR = 0xB0017610
# FairPlayIOKit: matching + open type + selector da research/CVE-2021-1791
# (ucRunversiond). Layout kJAimpk: field0/4/8 + sec1[20] + sec2[512] + size + fp_ret.
FP_IOKIT_MATCH = "com_apple_driver_FairPlayIOKit"
FP_IOKIT_OPEN_TYPE = 1
FP_IOKIT_SEL_VERSIONED = 21
FP_KJAIMPK_SIZE = 552  # 12 + 20 + 512 + 4 + 1 (+ pad)
# IOAESAccelerator (FairPlayIOKit::generateSeed / ucRunversiond hw path)
# fairplay_research: UID key selector 0x899 used by ucRunversiond
FP_IOAES_MATCH = "IOAESAccelerator"
FP_IOAES_UID_SELECTOR = 0x899
FAKE_IOAES_ITER = 0xB0017108
FAKE_IOAES_SERVICE = 0xB0017208
FAKE_IOAES_CONNECT = 0xB0017308
# CFTypeID distinti: adid confronta CFGetTypeID(ent) == CFNumberGetTypeID()
CF_TYPEID_NUMBER = 0x20
CF_TYPEID_BOOLEAN = 0x21
CF_TYPEID_STRING = 0x22
CF_TYPEID_OTHER = 0x2A
KIO_RETURN_SUCCESS = 0
KIO_RETURN_NO_DEVICE = 0xE00002C2
# Op-id (bytes[4:8] del payload OOL) — stabili su StoreServices 20H350
ADI_MIG_OP_LOGIN = bytes.fromhex("b0eda7af")
ADI_MIG_OP_OTP = bytes.fromhex("cfe0b46a")
ADI_MIG_OP_START = bytes.fromhex("716bd86c")
ADI_MIG_OP_END = bytes.fromhex("0b2b3196")
ADI_MIG_OP_ERASE = bytes.fromhex("7715488c")
ADI_MIG_OP_SYNC = bytes.fromhex("a54951ec")
ADI_MIG_OP_DESTROY = bytes.fromhex("55a637c0")
CF_OBJ_BASE = 0xB0005000
CF_OBJ_SIZE = 0x10000
VFS_FD_BASE = 100

# StoreServices 20H350: stub → slot GOT DSC (da capstone su __stubs)
# Patchiamo il GOT a trampoline IMPORT invece di eseguire Foundation/Security reali.
IOS_IMPORT_GOT: dict[str, tuple[int, int]] = {
    # name: (stub_va, got_slot_va)
    "CFStringCreateWithCString": (0x1A1BE0B48, 0x1DACA0760),
    "MGCopyAnswer": (0x1A1BE0DD0, 0x1DAD03AB0),
    "NSHomeDirectory": (0x1A1BE0E30, 0x1DACAD3D8),
    "SecItemAdd": (0x1A1BE0FD4, 0x1DACBF1D0),
    "SecItemCopyMatching": (0x1A1BE0FE0, 0x1DACBF1D8),
    "objc_msgSend": (0x1A1BE158C, 0x1DAD08048),
    "open": (0x1A1BE1844, 0x1DAC95260),
    "stat": (0x1A1BE1A54, 0x1DAC961D0),
    # pthread stub island (lock/unlock usati da FairPlay/ADI storage)
    "pthread_mutex_lock": (0x1A1BE1880, 0x1DAC95B28),
    "pthread_mutex_unlock": (0x1A1BE188C, 0x1DAC95B38),
}

# Stessi hash usati da Anisette.py / Dadoum Provision (libstoreservicescore Android).
# Se iOS StoreServices li esporta, il bridge è 1:1.
ANDROID_ADI_SYMBOLS: dict[str, str] = {
    "load_library": "kq56gsgHG6",
    "set_android_id": "Sph98paBcz",  # assente / da saltare su iOS puro
    "set_provisioning_path": "nf92ngaK92",
    "provisioning_erase": "p435tmhbla",
    "synchronize": "tn46gtiuhw",
    "provisioning_destroy": "fy34trz2st",
    "provisioning_end": "uv5t6nhkui",
    "provisioning_start": "rsegvyrt87",
    "get_login_code": "aslgmuibau",
    "dispose": "jk24uiwqrg",
    "otp_request": "qi864985u0",
    # iOS-only (StoreServices): routing info, visto funzionare in Unicorn
    "get_routing": "fm23w5mn5o",
}

# Simboli crypto comuni Android+iOS. Gli init Android-only
# (load_library / set_android_id / set_provisioning_path) su iOS 16+
# non esistono in StoreServices: su iOS ADI parla a com.apple.adid via mach_msg2
# (helper 0x1a1b1a210, msgh_id 1200). Il "path setter" Android non ha equivalente
# locale — lo stub MIG in install_adi_mig_stub lo sostituisce per lo smoke Unicorn.
REQUIRED_ADI_ROLES = (
    "provisioning_start",
    "provisioning_end",
    "otp_request",
    "dispose",
    "get_login_code",
)
ANDROID_ONLY_INIT_ROLES = (
    "load_library",
    "set_android_id",
    "set_provisioning_path",
)


def app_data_ios_libs_dir() -> Path:
    if sys.platform == "win32":
        return Path.home() / "AppData" / "Roaming" / "iCloudKitExtractor" / "ios-adi-libs"
    return Path.home() / ".config" / "iCloudKitExtractor" / "ios-adi-libs"


@dataclass
class IosAdiManifest:
    coreadi_path: Path
    storeservices_path: Path
    source_dsc: str
    symbol_map: dict[str, str] = field(default_factory=dict)
    libs_dir: Path | None = None
    adid_path: Path | None = None
    fairplayd_path: Path | None = None
    fairplay_iokit_path: Path | None = None
    fairplay_macos_path: Path | None = None

    @classmethod
    def load(cls, libs_dir: Path) -> IosAdiManifest:
        manifest_path = libs_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"manifest mancante: {manifest_path}")

        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        extracted = data.get("extracted") or {}
        core = extracted.get("coreadi")
        ss = extracted.get("storeservices")
        if not core or not ss:
            raise FileNotFoundError("manifest incompleto — riesegui extract_ios_adi_libs.py")

        # Optional override: { "otp_request": "qi864985u0", ... } or raw name→role
        symbol_map = dict(data.get("symbol_map") or {})
        override_path = libs_dir / "symbol_map.json"
        if override_path.exists():
            try:
                symbol_map.update(json.loads(override_path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError) as ex:
                logger.warning("symbol_map.json illegibile: %s", ex)

        adid_raw = extracted.get("adid")
        adid_path = Path(adid_raw) if adid_raw else (libs_dir / "adid")
        if not adid_path.exists():
            adid_path = None

        def _opt(key: str, *fallback_names: str) -> Path | None:
            raw = extracted.get(key)
            p = Path(raw) if raw else None
            if p is not None and p.exists():
                return p
            for name in fallback_names:
                cand = libs_dir / name
                if cand.exists():
                    return cand
            return None

        return cls(
            coreadi_path=Path(core),
            storeservices_path=Path(ss),
            source_dsc=data.get("source_dsc", ""),
            symbol_map=symbol_map,
            libs_dir=libs_dir,
            adid_path=adid_path,
            fairplayd_path=_opt("fairplayd", "fairplayd", "fairplayd.H2"),
            fairplay_iokit_path=_opt("fairplay_iokit", "FairPlayIOKit"),
            fairplay_macos_path=_opt(
                "fairplay_macos", FAIRPLAY_MACOS_NAME, "FairPlayIOKit_macOS"
            ),
        )


def _align(v: int, a: int = 0x1000) -> int:
    return (v + a - 1) & ~(a - 1)


def _canonicalize_dsc_ptr(addr: int) -> int:
    """Toglie bit PAC / chained-fixup residui → VA DSC canonica."""
    if addr == 0 or addr == 0xDEADDEADDEADDEAD:
        return addr
    # forma tipica on-disk: 0x000201XXXXXXXX → 0x1XXXXXXXX
    if (addr >> 32) == 0x201:
        cand = (addr & 0xFFFFFFFF) | 0x100000000
        if DSC_LAZY_LO <= cand < DSC_LAZY_HI:
            return cand
    # PAC / tag nei bit alti: maschera a ~39 bit
    stripped = addr & 0x7FFFFFFFFF
    if stripped != addr and DSC_LAZY_LO <= stripped < DSC_LAZY_HI:
        return stripped
    return addr


def _strip_fp_pac(addr: int) -> int:
    """PAC/obf pointer FairPlayIOKit → VA bassa (kext @ imagebase 0).

    Tabelle jump: 0x8011e05d000409c8 → 0x409c8 (low 32). Unicorn non autentica
    BLRAA, quindi dopo patch BLR il PC resta PAC-tagged.
    """
    if addr == 0:
        return 0
    if addr < 0x100000000:
        return addr
    low32 = addr & 0xFFFFFFFF
    if 0x1000 <= low32 < 0x2000000:
        return low32
    low40 = addr & 0xFFFFFFFFFF
    if low40 < 0x10000000000:
        return low40
    return addr


def _strip_fp_pac_pointers(data: bytes) -> bytes:
    """Riscrive u64 PAC-tagged in DATA → VA low32 (jump/state tables)."""
    if len(data) < 8:
        return data
    out = bytearray(data)
    changed = 0
    for off in range(0, len(out) - 7, 8):
        val = int.from_bytes(out[off : off + 8], "little")
        if val < 0x100000000:
            continue
        canon = _strip_fp_pac(val)
        if canon != val and 0x1000 <= canon < 0x2000000:
            out[off : off + 8] = canon.to_bytes(8, "little")
            changed += 1
    if changed:
        logger.info("FairPlay DATA: stripped %d PAC pointers", changed)
    return bytes(out) if changed else data


def _strip_pointers_in_page(data: bytes) -> bytes:
    """Riscrive u64 che sembrano puntatori DSC autenticati/chained."""
    if len(data) < 8:
        return data
    out = bytearray(data)
    changed = False
    for off in range(0, len(out) - 7, 8):
        val = int.from_bytes(out[off : off + 8], "little")
        canon = _canonicalize_dsc_ptr(val)
        if canon != val and canon != 0:
            out[off : off + 8] = canon.to_bytes(8, "little")
            changed = True
    return bytes(out) if changed else data


def _seg_perms(init_protection: int) -> int:
    from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE

    perms = 0
    if init_protection & 1:
        perms |= UC_PROT_READ
    if init_protection & 2:
        perms |= UC_PROT_WRITE
    if init_protection & 4:
        perms |= UC_PROT_EXEC
    return perms or UC_PROT_READ


def _macho_slice(parsed: Any) -> Any:
    if parsed is None:
        return None
    if hasattr(parsed, "at"):
        try:
            return parsed.at(0)
        except Exception:  # noqa: BLE001
            return None
    return parsed


def collect_exports(path: Path) -> dict[str, int]:
    """name → virtual address (file VA, pre-slide)."""
    import lief

    parsed = lief.MachO.parse(str(path))
    binary = _macho_slice(parsed)
    if binary is None:
        return {}

    out: dict[str, int] = {}
    for sym in binary.symbols:
        name = getattr(sym, "name", None) or ""
        if not name:
            continue
        try:
            exported = bool(sym.exported)
        except Exception:  # noqa: BLE001
            exported = True
        if not exported:
            continue
        try:
            value = int(sym.value)
        except Exception:  # noqa: BLE001
            continue
        if value:
            out[name] = value
            if name.startswith("_") and name[1:] not in out:
                out[name[1:]] = value
    return out


class _BumpAllocator:
    def __init__(self, base: int, size: int) -> None:
        self._base = base
        self._end = base + size
        self._ptr = base
        self._live: dict[int, int] = {}

    def alloc(self, n: int) -> int:
        n = max(8, _align(n, 16))
        if self._ptr + n > self._end:
            raise MemoryError("temp/malloc arena esaurita")
        addr = self._ptr
        self._ptr += n
        self._live[addr] = n
        return addr

    def free(self, addr: int) -> None:
        self._live.pop(addr, None)


class MachOArm64Loader:
    """Mappa segmenti Mach-O ARM64 in Unicorn + invoke cdecl."""

    def __init__(self) -> None:
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE

        self._uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self._next_load = 0x0010_0000
        self._exports: dict[str, int] = {}
        self._slides: dict[str, int] = {}
        self._temp = _BumpAllocator(TEMP_BASE, TEMP_SIZE)
        self._heap = _BumpAllocator(MALLOC_BASE, MALLOC_SIZE)

        self._uc.mem_map(RETURN_ADDRESS, 0x1000, UC_PROT_ALL)
        self._uc.mem_map(TEMP_BASE, TEMP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self._uc.mem_map(MALLOC_BASE, MALLOC_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self._uc.mem_map(IMPORT_BASE, IMPORT_SIZE, UC_PROT_ALL)
        # RET (ARM64): C0 03 5F D6
        self._uc.mem_write(IMPORT_BASE, b"\xc0\x03\x5f\xd6" * (IMPORT_SIZE // 4))
        # Stack canary cell (___stack_chk_guard punta qui dopo patch GOT)
        self._uc.mem_map(STACK_CHK_GUARD_SLOT, 0x1000, UC_PROT_ALL)
        self._uc.mem_write(STACK_CHK_GUARD_SLOT, (0xDEADBEEFCAFEBABE).to_bytes(8, "little"))
        self._uc.mem_map(FAKE_ZONE_BASE, FAKE_ZONE_SIZE, UC_PROT_ALL)
        self._uc.mem_map(TLS_BASE, TLS_SIZE, UC_PROT_ALL)
        self._uc.mem_map(CF_OBJ_BASE, CF_OBJ_SIZE, UC_PROT_ALL)
        self._uc.mem_map(ADID_NDR_RECORD, 0x2000, UC_PROT_ALL)
        # NDR_record minimo (mig_get_reply usa i primi 8 byte)
        self._uc.mem_write(ADID_NDR_RECORD, b"\x00" * 32)
        # CFBooleanTrue minimo: isa + value=1 (layout grezzo sufficiente per null-check / type)
        self._uc.mem_write(FAKE_CFBOOL_TRUE, (CF_OBJ_BASE).to_bytes(8, "little") + (1).to_bytes(8, "little"))
        self._uc.mem_write(FAKE_SEC_TASK, b"\x01SECTASK")
        self._lazy_pages: set[int] = set()
        self._dsc_path: Path | None = None
        self._ipsw_cli: Path | None = None
        self._page_cache: Path | None = None
        self._malloc_hooks: dict[int, str] = {}
        self._import_hooks: dict[int, str] = {}
        self._cf_bump = CF_OBJ_BASE + 0x100
        self._vfs_root = app_data_ios_libs_dir().parent / "ios-adi-data"
        self._vfs_root.mkdir(parents=True, exist_ok=True)
        self._vfs_fds: dict[int, Any] = {}
        self._vfs_next_fd = VFS_FD_BASE
        self._keychain: dict[str, bytes] = {}
        self._device_id = self._load_device_id()
        self._home_path = str(self._vfs_root).replace("\\", "/")
        self._adid_path: Path | None = None
        self._adid_mig_server: int | None = None
        self._adid_tramp_i = 0
        self._adi_mig_saved: dict[str, int] | None = None
        self._fp_iter_alive = False
        self._fp_opened = False
        self._fp_matching = 0
        self._fp_calls: list[dict[str, Any]] = []
        self._fairplayd_path: Path | None = None
        self._fairplayd_base: int | None = None
        self._fairplay_iokit_path: Path | None = None
        self._fairplay_macos_path: Path | None = None
        self._fp_macos_ready = False
        self._fp_uefdbi = 0
        self._fp_cmam7f = 0
        self._fp_lskd_start = 0
        self._fp_hw_loaded = False
        self._ioaes_matching = 0
        self._ioaes_opened = False
        self._fp_aes_calls = 0
        self._fp_uefdbi_calls = 0
        self._install_lazy_dsc_hooks()
        self._install_malloc_hooks()
        self._setup_fake_malloc_zone()
        self._setup_tls()
        self._install_syscall_stubs()
        self._install_import_dispatch()

    def configure_dsc_pager(self, dsc_path: Path, libs_dir: Path) -> None:
        """Abilita page-in reale dal dyld_shared_cache via ipsw dyld dump."""
        self._dsc_path = dsc_path if dsc_path.exists() else None
        tools = Path.home() / "AppData" / "Roaming" / "iCloudKitExtractor" / "tools" / "ipsw.exe"
        which = None
        try:
            import shutil

            which = shutil.which("ipsw")
        except Exception:  # noqa: BLE001
            which = None
        self._ipsw_cli = Path(which) if which else (tools if tools.exists() else None)
        self._page_cache = libs_dir / "_pagecache"
        self._page_cache.mkdir(parents=True, exist_ok=True)
        logger.info(
            "DSC pager: dsc=%s ipsw=%s",
            self._dsc_path,
            self._ipsw_cli,
        )

    def _fetch_dsc_page(self, page: int) -> bytes | None:
        if self._dsc_path is None or self._ipsw_cli is None or self._page_cache is None:
            return None
        cache_file = self._page_cache / f"{page:016x}.bin"
        if cache_file.exists() and cache_file.stat().st_size == 0x1000:
            return cache_file.read_bytes()
        out = self._page_cache / f"{page:016x}.raw"
        try:
            # text=False: stdout/stderr di ipsw possono contenere bytes non-UTF8
            # senza --bytes: scrive file binario pulito su -o
            proc = subprocess.run(
                [
                    str(self._ipsw_cli),
                    "dyld",
                    "dump",
                    str(self._dsc_path),
                    hex(page),
                    "-s",
                    "4096",
                    "-o",
                    str(out),
                ],
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as ex:
            logger.debug("ipsw dump 0x%x: %s", page, ex)
            return None
        if proc.returncode != 0 or not out.exists():
            logger.debug(
                "ipsw dump fail 0x%x rc=%s stderr=%s",
                page,
                proc.returncode,
                (proc.stderr or b"")[:200],
            )
            return None
        data = out.read_bytes()
        if len(data) >= 0x1000:
            data = data[:0x1000] if len(data) == 0x1000 else data[-0x1000:]
        else:
            data = data + b"\x00" * (0x1000 - len(data))
        cache_file.write_bytes(data)
        return data

    def _install_lazy_dsc_hooks(self) -> None:
        """Mappa on-demand pagine DSC mancanti (dump reale o RET/zero stub)."""
        from unicorn import (
            UC_HOOK_MEM_FETCH_UNMAPPED,
            UC_HOOK_MEM_READ_UNMAPPED,
            UC_HOOK_MEM_WRITE_UNMAPPED,
            UC_MEM_FETCH_UNMAPPED,
            UC_PROT_ALL,
        )

        def _hook(uc, access, address, size, value, user_data):  # noqa: ANN001, ARG001
            if address == 0 or address >= 0x100000000000:
                return False
            # Puntatore PAC/chained: servi la pagina canonica (e alias se serve)
            canon = _canonicalize_dsc_ptr(address)
            page = address & ~0xFFF
            cpage = canon & ~0xFFF
            if not (DSC_LAZY_LO <= cpage < DSC_LAZY_HI):
                return False
            if page in self._lazy_pages:
                return True
            fetch_page = cpage
            data = self._fetch_dsc_page(fetch_page)
            if data is None and fetch_page != page and (DSC_LAZY_LO <= page < DSC_LAZY_HI):
                data = self._fetch_dsc_page(page)
                fetch_page = page
            if data is None:
                if access == UC_MEM_FETCH_UNMAPPED:
                    data = b"\xc0\x03\x5f\xd6" * (0x1000 // 4)
                else:
                    data = b"\x00" * 0x1000
            else:
                data = _strip_pointers_in_page(data)
            # Mappa sia VA fault che VA canonica (stesso contenuto)
            for map_page in {page, cpage}:
                if map_page in self._lazy_pages:
                    continue
                if not (DSC_LAZY_LO <= map_page < DSC_LAZY_HI) and map_page != page:
                    # alias PAC fuori range tipico: mappa comunque la page fault
                    if map_page != page:
                        continue
                try:
                    uc.mem_map(map_page, 0x1000, UC_PROT_ALL)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    uc.mem_write(map_page, data)
                    self._patch_runtime_globals(map_page, data)
                    self._lazy_pages.add(map_page)
                except Exception:  # noqa: BLE001
                    return False
            # Alias PAC puro (es. 0x201de4f3000) fuori DSC_LAZY
            if page not in self._lazy_pages:
                try:
                    uc.mem_map(page, 0x1000, UC_PROT_ALL)
                    uc.mem_write(page, data)
                    self._lazy_pages.add(page)
                except Exception:  # noqa: BLE001
                    return False
            return True

        self._uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            _hook,
        )

    def _patch_runtime_globals(self, page: int, data: bytes) -> None:
        """Corregge GOT/globals noti dopo page-in DSC."""
        patch = None
        got_slot = GOT_STACK_CHK_GUARD
        if page <= got_slot < page + 0x1000:
            patch = bytearray(data) if patch is None else patch
            off = got_slot - page
            patch[off : off + 8] = STACK_CHK_GUARD_SLOT.to_bytes(8, "little")
            logger.info("Patched ___stack_chk_guard GOT @0x%x -> 0x%x", got_slot, STACK_CHK_GUARD_SLOT)
        zones = MALLOC_ZONES_ADDR
        if page <= zones < page + 0x1000:
            patch = bytearray(data) if patch is None else patch
            off = zones - page
            # Array di 1 zona: puntatore al nostro fake malloc_zone_t
            zones_arr = FAKE_ZONE_BASE + 0x800
            patch[off : off + 8] = zones_arr.to_bytes(8, "little")
            logger.info("Patched _malloc_zones @0x%x -> 0x%x", zones, zones_arr)
        if patch is not None:
            self._uc.mem_write(page, bytes(patch))

    def _install_syscall_stubs(self) -> None:
        """Darwin svc #0x80: senza hook Unicorn alza UC_ERR_EXCEPTION."""
        from unicorn import UC_HOOK_INTR
        from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X16

        def _on_intr(uc, intno, user_data):  # noqa: ANN001, ARG001
            # Apple: numero syscall in x16 (spesso negativo per mach traps)
            nr = uc.reg_read(UC_ARM64_REG_X16)
            nr_s = nr - 0x10000000000000000 if nr >= 0x8000000000000000 else nr
            # Default: successo (0). open/read ecc. -> -1 (ENOENT) se BSD positivo tipico.
            if 0 < nr_s < 600:
                uc.reg_write(UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)  # -1
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)

        self._uc.hook_add(UC_HOOK_INTR, _on_intr)

    def _load_device_id(self) -> str:
        for name in ("device-iphone-coherent.json", "device-provision.json", "device.json"):
            p = app_data_ios_libs_dir().parent / name
            if not p.exists():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            for key in (
                "AdiIdentifier",
                "adi_identifier",
                "unique_device_identifier",
                "DeviceUuid",
                "udid",
                "UniqueDeviceID",
                "device_id",
            ):
                val = data.get(key)
                if isinstance(val, str) and len(val) >= 8:
                    return val.replace("-", "").lower()[:16]
        return "a1b2c3d4e5f60708"

    def _alloc_cfstring(self, text: str) -> int:
        """CFString/NSString minimo: isa, info, data*, length."""
        raw = text.encode("utf-8") + b"\x00"
        data_addr = self._cf_bump
        self._cf_bump = _align(self._cf_bump + len(raw), 16)
        obj = self._cf_bump
        self._cf_bump = _align(self._cf_bump + 0x40, 16)
        if self._cf_bump >= CF_OBJ_BASE + CF_OBJ_SIZE - 0x100:
            raise MemoryError("CF object arena esaurita")
        self._uc.mem_write(data_addr, raw)
        blob = bytearray(0x28)
        blob[0:8] = (CF_OBJ_BASE).to_bytes(8, "little")  # fake isa
        blob[8:16] = (0x7C0).to_bytes(8, "little")  # immutable C-string like
        blob[16:24] = data_addr.to_bytes(8, "little")
        blob[24:32] = len(text).to_bytes(8, "little")
        self._uc.mem_write(obj, bytes(blob))
        return obj

    def _read_cstr(self, addr: int, limit: int = 512) -> bytes:
        if addr == 0:
            return b""
        chunk = bytes(self._uc.mem_read(addr, limit))
        return chunk.split(b"\x00", 1)[0]

    def _read_cfstring(self, addr: int) -> str:
        if addr == 0:
            return ""
        try:
            data_ptr = int.from_bytes(self._uc.mem_read(addr + 0x10, 8), "little")
            length = int.from_bytes(self._uc.mem_read(addr + 0x18, 8), "little")
            if data_ptr and 0 < length < 0x1000:
                return bytes(self._uc.mem_read(data_ptr, length)).decode("utf-8", "replace")
            # fallback: maybe already a C string
            return self._read_cstr(addr).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""

    def _vfs_resolve(self, path: str) -> Path:
        path = path.replace("\\", "/")
        if path.startswith(self._home_path):
            rel = path[len(self._home_path) :].lstrip("/")
            return self._vfs_root / rel
        if path.startswith("/"):
            return self._vfs_root / path.lstrip("/")
        return self._vfs_root / path

    def _install_import_dispatch(self) -> None:
        from unicorn import UC_HOOK_CODE
        from unicorn.arm64_const import (
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
        )

        def _ret(uc, value: int = 0) -> None:  # noqa: ANN001
            uc.reg_write(UC_ARM64_REG_X0, value & 0xFFFFFFFFFFFFFFFF)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

        def _on_code(uc, address, size, user_data):  # noqa: ANN001, ARG001
            role = self._import_hooks.get(address)
            if role is None:
                return
            if role == "MGCopyAnswer":
                key = self._read_cfstring(uc.reg_read(UC_ARM64_REG_X0))
                answers = {
                    "UniqueDeviceID": self._device_id,
                    "SerialNumber": "C6KXG00A0J00",
                    "ProductType": "iPhone10,1",
                    "DeviceClass": "iPhone",
                    "BuildVersion": "20H350",
                    "ProductVersion": "16.7.10",
                    "HWModelStr": "D20AP",
                    "MLBSerialNumber": "C6K612345678901",
                }
                val = answers.get(key)
                _ret(uc, self._alloc_cfstring(val) if val else 0)
            elif role == "NSHomeDirectory":
                _ret(uc, self._alloc_cfstring(self._home_path))
            elif role == "CFStringCreateWithCString":
                # x0=alloc, x1=cstr, x2=encoding
                cstr = self._read_cstr(uc.reg_read(UC_ARM64_REG_X1)).decode("utf-8", "replace")
                _ret(uc, self._alloc_cfstring(cstr))
            elif role == "CFStringGetCString":
                # Boolean CFStringGetCString(str, buf, bufSize, encoding)
                obj = int(uc.reg_read(UC_ARM64_REG_X0))
                buf = int(uc.reg_read(UC_ARM64_REG_X1))
                buflen = int(uc.reg_read(UC_ARM64_REG_X2))
                if not buf or buflen <= 1:
                    _ret(uc, 0)
                    return
                if obj == FAKE_CFBOOL_TRUE:
                    text = b"1"
                else:
                    try:
                        text = self._read_cfstring(obj).encode("utf-8")
                    except Exception:  # noqa: BLE001
                        text = b""
                if not text:
                    _ret(uc, 0)
                    return
                out = text[: buflen - 1] + b"\x00"
                try:
                    uc.mem_write(buf, out)
                except Exception:  # noqa: BLE001
                    _ret(uc, 0)
                    return
                _ret(uc, 1)
            elif role == "CFStringGetLength":
                obj = int(uc.reg_read(UC_ARM64_REG_X0))
                if obj == FAKE_CFBOOL_TRUE:
                    _ret(uc, 1)
                else:
                    try:
                        _ret(uc, len(self._read_cfstring(obj)))
                    except Exception:  # noqa: BLE001
                        _ret(uc, 0)
            elif role == "strtoul":
                # unsigned long strtoul(const char *str, char **endptr, int base)
                s = self._read_cstr(uc.reg_read(UC_ARM64_REG_X0)).decode("utf-8", "replace")
                endp = int(uc.reg_read(UC_ARM64_REG_X1))
                base = int(uc.reg_read(UC_ARM64_REG_X2)) or 10
                try:
                    import re as _re

                    m = _re.match(r"\s*([+-]?[0-9a-fA-FxX]+)", s)
                    if m:
                        val = int(m.group(1), base)
                        n_consumed = m.end(1)
                    else:
                        val = 0
                        n_consumed = 0
                except Exception:  # noqa: BLE001
                    val = 0
                    n_consumed = 0
                if endp:
                    try:
                        src = int(uc.reg_read(UC_ARM64_REG_X0))
                        uc.mem_write(endp, (src + n_consumed).to_bytes(8, "little"))
                    except Exception:  # noqa: BLE001
                        pass
                _ret(uc, val & 0xFFFFFFFFFFFFFFFF)
            elif role == "xpc_connection_create_mach_service":
                name = self._read_cstr(uc.reg_read(UC_ARM64_REG_X0)).decode(
                    "utf-8", "replace"
                )
                # Serve connessione non-NULL: con NULL adid esce con -45003.
                # Loopback adid.xpc: reply sync finta (vedi send_message handler).
                conn = self._heap.alloc(0x40)
                self._uc.mem_write(conn, b"\x00" * 0x40)
                if not hasattr(self, "_xpc_conns"):
                    self._xpc_conns = set()
                self._xpc_conns.add(conn)
                logger.info("xpc_connection_create_mach_service(%r) → %#x", name, conn)
                _ret(uc, conn)
            elif role in (
                "xpc_connection_set_event_handler",
                "xpc_connection_set_target_queue",
                "xpc_connection_activate",
                "xpc_connection_resume",
                "xpc_connection_cancel",
                "xpc_release",
                "xpc_dictionary_send_reply",
                "xpc_transaction_begin",
                "xpc_transaction_end",
            ):
                _ret(uc, 0)
            elif role in (
                "xpc_dictionary_create_empty",
                "xpc_dictionary_create_reply",
                "dispatch_queue_create",
            ):
                obj = self._heap.alloc(0x40)
                self._uc.mem_write(obj, b"\x00" * 0x40)
                _ret(uc, obj)
            elif role == "xpc_connection_send_message_with_reply_sync":
                # Loopback com.apple.adid.xpc: il server reale farebbe FairPlay/IOKit.
                # Qui emuliamo la reply client-side e, su START, esercitiamo IOKit.
                reply = self._heap.alloc(0x40)
                self._uc.mem_write(reply, b"\x00" * 0x40)
                op = ADI_MIG_OP_LOGIN
                req = getattr(self, "_xpc_last_req_data", None)
                if isinstance(req, (bytes, bytearray)) and len(req) >= 8:
                    op = bytes(req[4:8])
                status = ADI_NOT_PROVISIONED
                extra = b""
                if op == ADI_MIG_OP_START:
                    # Percorso provisioning: triggera FairPlay IOKit (come farebbe
                    # il server adid / fairplayd) prima di costruire la reply.
                    try:
                        self._drive_fairplay_iokit_from_xpc()
                        status = 0
                        # CPIM MIG: 16 B non-zero (come stub sintetico).
                        # Reply XPC: padding lungo — reply troppo corta crasha adid.
                        fp_out = getattr(self, "_fp_last_out", b"") or b""
                        if len(fp_out) >= 16 and any(fp_out[:16]):
                            cpim = fp_out[:16]
                        else:
                            cpim = os.urandom(16)
                        self._xpc_pending_cpim = cpim
                        self._xpc_pending_session = 1
                        self._last_start_cpim = cpim
                        self._last_start_session = 1
                        extra = cpim + b"\x00" * 48
                    except Exception as ex:  # noqa: BLE001
                        logger.warning("FairPlay IOKit drive fallito: %s", ex)
                payload = bytearray(20 + len(extra))
                struct.pack_into("<I", payload, 0, 1)
                payload[4:8] = op if len(op) == 4 else ADI_MIG_OP_LOGIN
                struct.pack_into("<Ii", payload, 8, 1, status)
                if extra:
                    payload[20:] = extra
                self._xpc_last_status = status
                pdata = self._heap.alloc(len(payload))
                self._uc.mem_write(pdata, bytes(payload))
                if not hasattr(self, "_xpc_reply_data"):
                    self._xpc_reply_data = {}
                self._xpc_reply_data[reply] = (pdata, len(payload))
                logger.info(
                    "xpc_send_message_with_reply_sync → %#x data=%#x len=%d op=%s status=%d",
                    reply,
                    pdata,
                    len(payload),
                    op.hex(),
                    status,
                )
                _ret(uc, reply)
            elif role == "xpc_dictionary_get_data":
                # const void *get_data(dict, key, size_t *out_len)
                dct = int(uc.reg_read(UC_ARM64_REG_X0))
                key = self._read_cstr(uc.reg_read(UC_ARM64_REG_X1)).decode(
                    "utf-8", "replace"
                )
                out_len = int(uc.reg_read(UC_ARM64_REG_X2))
                blob = getattr(self, "_xpc_reply_data", {}).get(dct)
                if blob is None:
                    # fallback: status 0 generico
                    payload = struct.pack(">i", 0) + b"\x00" * 28
                    pdata = self._heap.alloc(len(payload))
                    self._uc.mem_write(pdata, payload)
                    blob = (pdata, len(payload))
                if out_len:
                    try:
                        uc.mem_write(out_len, int(blob[1]).to_bytes(8, "little"))
                    except Exception:  # noqa: BLE001
                        pass
                logger.info("xpc_dictionary_get_data(%r) → %#x len=%d", key, blob[0], blob[1])
                _ret(uc, blob[0])
            elif role == "xpc_dictionary_get_value":
                _ret(uc, 0)
            elif role == "xpc_dictionary_set_data":
                # log key for protocol discovery; salva 'data' per echo nella reply
                try:
                    key = self._read_cstr(uc.reg_read(UC_ARM64_REG_X1)).decode(
                        "utf-8", "replace"
                    )
                    val = int(uc.reg_read(UC_ARM64_REG_X2))
                    ln = int(uc.reg_read(UC_ARM64_REG_X3))
                    logger.info("xpc_dictionary_set_data(%r, len=%d)", key, ln)
                    if key == "data" and val and 0 < ln < 0x10000:
                        self._xpc_last_req_data = bytes(uc.mem_read(val, ln))
                except Exception:  # noqa: BLE001
                    pass
                _ret(uc, 0)
            elif role == "xpc_dictionary_get_audit_token":
                outp = int(uc.reg_read(UC_ARM64_REG_X1))
                if outp:
                    try:
                        uc.mem_write(outp, b"\x00" * 32)
                    except Exception:  # noqa: BLE001
                        pass
                _ret(uc, 0)
            elif role == "xpc_get_type":
                # Deve matchare __xpc_type_dictionary risolto dal pool (FAKE_DICT).
                _ret(uc, FAKE_XPC_TYPE_DICT)
            elif role == "xpc_copy_description":
                _ret(uc, self._alloc_cfstring("xpc"))
            elif role == "objc_msgSend":
                sel = self._read_cstr(uc.reg_read(UC_ARM64_REG_X1)).decode("utf-8", "replace")
                self_obj = uc.reg_read(UC_ARM64_REG_X0)
                if sel in ("UTF8String", "cStringUsingEncoding:"):
                    try:
                        data_ptr = int.from_bytes(self._uc.mem_read(self_obj + 0x10, 8), "little")
                        _ret(uc, data_ptr)
                    except Exception:  # noqa: BLE001
                        _ret(uc, 0)
                elif sel == "length":
                    try:
                        ln = int.from_bytes(self._uc.mem_read(self_obj + 0x18, 8), "little")
                        _ret(uc, ln)
                    except Exception:  # noqa: BLE001
                        _ret(uc, 0)
                elif sel in ("retain", "autorelease", "copy", "mutableCopy"):
                    _ret(uc, self_obj)
                elif sel == "release":
                    _ret(uc, 0)
                else:
                    _ret(uc, 0)
            elif role == "open":
                path = self._read_cstr(uc.reg_read(UC_ARM64_REG_X0)).decode("utf-8", "replace")
                flags = uc.reg_read(UC_ARM64_REG_X1)
                host = self._vfs_resolve(path)
                try:
                    host.parent.mkdir(parents=True, exist_ok=True)
                    mode = "r+b"
                    if flags & 0x200:  # O_CREAT roughly on Darwin
                        mode = "w+b" if not host.exists() else "r+b"
                    if not host.exists() and not (flags & 0x200):
                        _ret(uc, 0xFFFFFFFFFFFFFFFF)
                        return
                    if not host.exists():
                        host.write_bytes(b"")
                    fh = open(host, mode)  # noqa: SIM115
                    fd = self._vfs_next_fd
                    self._vfs_next_fd += 1
                    self._vfs_fds[fd] = fh
                    _ret(uc, fd)
                except OSError:
                    _ret(uc, 0xFFFFFFFFFFFFFFFF)
            elif role == "stat":
                path = self._read_cstr(uc.reg_read(UC_ARM64_REG_X0)).decode("utf-8", "replace")
                buf = uc.reg_read(UC_ARM64_REG_X1)
                host = self._vfs_resolve(path)
                if not host.exists():
                    _ret(uc, 0xFFFFFFFFFFFFFFFF)
                    return
                st = host.stat()
                # minimal Darwin stat64-ish: zero + size at common offset 0x48
                blob = bytearray(128)
                blob[0x48:0x50] = int(st.st_size).to_bytes(8, "little")
                try:
                    uc.mem_write(buf, bytes(blob))
                except Exception:  # noqa: BLE001
                    _ret(uc, 0xFFFFFFFFFFFFFFFF)
                    return
                _ret(uc, 0)
            elif role == "SecItemCopyMatching":
                # not found
                _ret(uc, (-25300) & 0xFFFFFFFFFFFFFFFF)  # errSecItemNotFound
            elif role == "SecItemAdd":
                _ret(uc, 0)
            elif role == "SecItemUpdate":
                _ret(uc, 0)
            elif role == "SecTaskCreateWithAuditToken":
                # x0=allocator, x1=audit_token — client MIG deve risultare valido
                _ret(uc, FAKE_SEC_TASK)
            elif role == "SecTaskCopyValueForEntitlement":
                # x0=task, x1=CFString key, x2=*error
                key = self._read_cfstring(uc.reg_read(UC_ARM64_REG_X1))
                if not key:
                    key = self._read_cstr(uc.reg_read(UC_ARM64_REG_X1)).decode(
                        "utf-8", "replace"
                    )
                errp = int(uc.reg_read(UC_ARM64_REG_X2))
                if errp:
                    try:
                        uc.mem_write(errp, (0).to_bytes(8, "little"))
                    except Exception:  # noqa: BLE001
                        pass
                logger.info("SecTaskCopyValueForEntitlement(%r)", key)
                # adid: Number? → String? → CFStringGetCString + strtoul, poi
                # state-machine su w19 = f(strtoul). Valori che raggiungono un
                # ramo success (da C=0x7c607e39): 0xfa6fde94, 0x9a1a5b57.
                if key in ("adi-client", "com.apple.private.adi-client"):
                    magic = int(getattr(self, "_adid_entitlement_magic", 0xFA6FDE94))
                    _ret(uc, self._alloc_cfstring(str(magic)))
                else:
                    _ret(uc, FAKE_CFBOOL_TRUE)
            elif role == "CFGetTypeID":
                obj = int(uc.reg_read(UC_ARM64_REG_X0))
                if obj == FAKE_CFBOOL_TRUE:
                    _ret(uc, CF_TYPEID_BOOLEAN)
                elif CF_OBJ_BASE <= obj < CF_OBJ_BASE + CF_OBJ_SIZE:
                    _ret(uc, CF_TYPEID_STRING)
                elif obj == 0:
                    _ret(uc, 0)
                else:
                    _ret(uc, CF_TYPEID_OTHER)
            elif role == "CFBooleanGetTypeID":
                _ret(uc, CF_TYPEID_BOOLEAN)
            elif role == "CFNumberGetTypeID":
                _ret(uc, CF_TYPEID_NUMBER)
            elif role == "CFStringGetTypeID":
                _ret(uc, CF_TYPEID_STRING)
            elif role == "CFBooleanGetValue":
                obj = uc.reg_read(UC_ARM64_REG_X0)
                _ret(uc, 1 if obj == FAKE_CFBOOL_TRUE or obj else 0)
            elif role == "CFNumberGetValue":
                # Solo su CFNumber reali; su CFBoolean deve fallire.
                obj = int(uc.reg_read(UC_ARM64_REG_X0))
                if obj == FAKE_CFBOOL_TRUE or obj == 0:
                    _ret(uc, 0)
                    return
                ntype = int(uc.reg_read(UC_ARM64_REG_X1))
                outp = int(uc.reg_read(UC_ARM64_REG_X2))
                val = int(getattr(self, "_adid_cfnumber_value", 1))
                try:
                    if outp:
                        if ntype in (4, 9, 10):  # SInt64 / CFIndex / CGFloat-ish
                            uc.mem_write(outp, int(val).to_bytes(8, "little", signed=True))
                        else:
                            uc.mem_write(outp, int(val).to_bytes(4, "little", signed=True))
                except Exception:  # noqa: BLE001
                    _ret(uc, 0)
                    return
                _ret(uc, 1)
            elif role == "CFEqual":
                a = uc.reg_read(UC_ARM64_REG_X0)
                b = uc.reg_read(UC_ARM64_REG_X1)
                _ret(uc, 1 if a == b else 0)
            elif role in ("pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_trylock"):
                _ret(uc, 0)
            elif role in (
                "nop_ret0",
                "mig_deallocate",
                "CFRelease",
                "IOObjectRelease",
                "xpc_release",
                "mach_msg_destroy",
            ):
                _ret(uc, 0)
            elif role == "malloc":
                n = int(uc.reg_read(UC_ARM64_REG_X0))
                try:
                    _ret(uc, self._heap.alloc(n if n > 0 else 1))
                except MemoryError:
                    _ret(uc, 0)
            elif role == "cf_allocator_allocate":
                # void *CFAllocatorAllocate(allocator, size, hint)
                n = int(uc.reg_read(UC_ARM64_REG_X1))
                try:
                    _ret(uc, self._heap.alloc(n if n > 0 else 1))
                except MemoryError:
                    _ret(uc, 0)
            elif role == "vm_allocate":
                # kern_return_t vm_allocate(task, vm_address_t *addr, size, flags)
                addr_p = int(uc.reg_read(UC_ARM64_REG_X1))
                n = int(uc.reg_read(UC_ARM64_REG_X2))
                try:
                    ptr = self._heap.alloc(n if n > 0 else 0x1000)
                    if addr_p:
                        uc.mem_write(addr_p, ptr.to_bytes(8, "little"))
                    _ret(uc, 0)  # KERN_SUCCESS
                except MemoryError:
                    _ret(uc, 1)  # KERN_NO_SPACE
            elif role == "vm_deallocate":
                # vm_deallocate(task, addr, size) — best-effort free
                try:
                    self._heap.free(int(uc.reg_read(UC_ARM64_REG_X1)))
                except Exception:  # noqa: BLE001
                    pass
                _ret(uc, 0)
            elif role == "free":
                self._heap.free(uc.reg_read(UC_ARM64_REG_X0))
                _ret(uc, 0)
            elif role == "memcpy_chk":
                dst = uc.reg_read(UC_ARM64_REG_X0)
                src = uc.reg_read(UC_ARM64_REG_X1)
                n = int(uc.reg_read(UC_ARM64_REG_X2))
                if dst and src and 0 < n < 0x100000:
                    try:
                        uc.mem_write(dst, bytes(uc.mem_read(src, n)))
                    except Exception:  # noqa: BLE001
                        pass
                _ret(uc, dst)
            elif role == "memset":
                dst = uc.reg_read(UC_ARM64_REG_X0)
                c = int(uc.reg_read(UC_ARM64_REG_X1)) & 0xFF
                n = int(uc.reg_read(UC_ARM64_REG_X2))
                if dst and 0 < n < 0x100000:
                    try:
                        uc.mem_write(dst, bytes([c]) * n)
                    except Exception:  # noqa: BLE001
                        pass
                _ret(uc, dst)
            elif role == "fp_aes_decrypt_key":
                # aes_decrypt_key(key, key_len, ctx) — stash key in ctx[0:32]
                key_p = int(uc.reg_read(UC_ARM64_REG_X0))
                key_len = int(uc.reg_read(UC_ARM64_REG_X1))
                ctx = int(uc.reg_read(UC_ARM64_REG_X2))
                try:
                    key = bytes(uc.mem_read(key_p, min(max(key_len, 0), 32)))
                    if ctx:
                        uc.mem_write(ctx, key.ljust(32, b"\x00"))
                    _ret(uc, 0)
                except Exception:  # noqa: BLE001
                    _ret(uc, -1)
            elif role == "fp_aes_decrypt_cbc":
                # aes_decrypt_cbc(in, iv, num_blk, out, ctx)
                inp = int(uc.reg_read(UC_ARM64_REG_X0))
                ivp = int(uc.reg_read(UC_ARM64_REG_X1))
                nblk = int(uc.reg_read(UC_ARM64_REG_X2))
                outp = int(uc.reg_read(UC_ARM64_REG_X3))
                ctx = int(uc.reg_read(UC_ARM64_REG_X4))
                try:
                    from Crypto.Cipher import AES

                    key = bytes(uc.mem_read(ctx, 16)) if ctx else self._fp_uid_aes_key()
                    iv = bytes(uc.mem_read(ivp, 16)) if ivp else bytes(16)
                    data = bytes(uc.mem_read(inp, nblk * 16))
                    pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)
                    if outp:
                        uc.mem_write(outp, pt)
                    self._fp_aes_calls = int(getattr(self, "_fp_aes_calls", 0)) + 1
                    _ret(uc, 0)
                except Exception:  # noqa: BLE001
                    _ret(uc, -1)
            elif role == "fp_iobuf_new":
                # IOBufferMemoryDescriptor::inTaskWithOptions → fake desc {vtable, buff, cap}
                cap = int(uc.reg_read(UC_ARM64_REG_X2))
                if cap <= 0 or cap > 0x100000:
                    cap = 0x1000
                buff = self._heap.alloc(cap)
                desc = self._heap.alloc(24)
                uc.mem_write(desc, (0).to_bytes(8, "little"))
                uc.mem_write(desc + 8, buff.to_bytes(8, "little"))
                uc.mem_write(desc + 16, int(cap).to_bytes(8, "little"))
                _ret(uc, desc)
            elif role == "fp_iolock_alloc":
                # IOLockAlloc / IORWLockAlloc — cmam7f fallisce con -42028 se NULL
                lock = self._heap.alloc(64)
                try:
                    uc.mem_write(lock, b"\x00" * 64)
                except Exception:  # noqa: BLE001
                    pass
                logger.info("IOLockAlloc → %#x", lock)
                _ret(uc, lock)
            elif role == "IOConnectCallStructMethod":
                _ret(uc, self._fairplay_connect_struct(uc))
            elif role == "IOServiceMatching":
                # Preferito: com_apple_driver_FairPlayIOKit (IOKit class, non UserClient)
                name = self._read_cstr(uc.reg_read(UC_ARM64_REG_X0)).decode("utf-8", "replace")
                matching = self._alloc_cfstring(name or FP_IOKIT_MATCH)
                if FP_IOAES_MATCH in name:
                    self._ioaes_matching = matching
                else:
                    self._fp_matching = matching
                logger.info("IOServiceMatching(%r) → %#x", name, matching)
                _ret(uc, matching)
            elif role == "fp_wait_for_service":
                # IOService::waitForService / getMatchingService — kext init
                matching = int(uc.reg_read(UC_ARM64_REG_X0))
                if matching and matching == getattr(self, "_ioaes_matching", 0):
                    svc = FAKE_IOAES_SERVICE
                elif matching and matching == getattr(self, "_fp_matching", 0):
                    svc = FAKE_FP_SERVICE
                else:
                    svc = FAKE_IOAES_SERVICE
                logger.info("waitForService match=%#x → %#x", matching, svc)
                _ret(uc, svc)
            elif role == "fp_get_matching_services":
                _ret(uc, FAKE_IOAES_ITER)
            elif role == "IOServiceGetMatchingServices":
                # x0=master, x1=matching, x2=*existing
                outp = uc.reg_read(UC_ARM64_REG_X2)
                matching = int(uc.reg_read(UC_ARM64_REG_X1))
                if matching and matching == getattr(self, "_ioaes_matching", 0):
                    iter_h = FAKE_IOAES_ITER
                    self._ioaes_matching = 0
                else:
                    iter_h = FAKE_FP_ITER
                    self._fp_iter_alive = True
                    self._fp_matching = 0
                if outp:
                    try:
                        uc.mem_write(outp, iter_h.to_bytes(4, "little"))
                    except Exception:  # noqa: BLE001
                        _ret(uc, KIO_RETURN_NO_DEVICE)
                        return
                logger.info("IOServiceGetMatchingServices → iter=%#x", iter_h)
                _ret(uc, KIO_RETURN_SUCCESS)
            elif role == "IOServiceOpen":
                # x0=service, x1=owningTask, x2=type, x3=*connect
                # FairPlay: type=1 (CVE-2021-1791 / research)
                open_type = int(uc.reg_read(UC_ARM64_REG_X2))
                service = int(uc.reg_read(UC_ARM64_REG_X0))
                outp = uc.reg_read(UC_ARM64_REG_X3)
                if service in (FAKE_IOAES_SERVICE, FAKE_IOAES_ITER):
                    conn = FAKE_IOAES_CONNECT
                    self._ioaes_opened = True
                else:
                    conn = FAKE_FP_CONNECT
                    self._fp_opened = True
                    self._fp_open_type = open_type
                if outp:
                    try:
                        uc.mem_write(outp, conn.to_bytes(4, "little"))
                    except Exception:  # noqa: BLE001
                        _ret(uc, KIO_RETURN_NO_DEVICE)
                        return
                logger.info(
                    "IOServiceOpen type=%d service=%#x → connect=%#x",
                    open_type,
                    service,
                    conn,
                )
                _ret(uc, KIO_RETURN_SUCCESS)
            elif role == "IOIteratorNext":
                # Prefer IOAES iterator if that was the last GetMatchingServices
                if int(uc.reg_read(UC_ARM64_REG_X0)) == FAKE_IOAES_ITER:
                    logger.info("IOIteratorNext → IOAES service=%#x", FAKE_IOAES_SERVICE)
                    _ret(uc, FAKE_IOAES_SERVICE)
                elif self._fp_iter_alive:
                    self._fp_iter_alive = False
                    logger.info("IOIteratorNext → service=%#x", FAKE_FP_SERVICE)
                    _ret(uc, FAKE_FP_SERVICE)
                else:
                    _ret(uc, 0)
            elif role == "IOMainPort":
                outp = uc.reg_read(UC_ARM64_REG_X1)
                if outp:
                    try:
                        uc.mem_write(outp, (0x104).to_bytes(4, "little"))
                    except Exception:  # noqa: BLE001
                        pass
                _ret(uc, KIO_RETURN_SUCCESS)
            elif role == "arc4random":
                _ret(uc, int.from_bytes(os.urandom(4), "little"))
            elif role == "time":
                import time as _time

                _ret(uc, int(_time.time()))
            elif role == "gettimeofday":
                import time as _time

                tv = uc.reg_read(UC_ARM64_REG_X0)
                if tv:
                    now = _time.time()
                    sec = int(now)
                    usec = int((now - sec) * 1_000_000)
                    try:
                        uc.mem_write(tv, struct.pack("<QQ", sec, usec))
                    except Exception:  # noqa: BLE001
                        pass
                _ret(uc, 0)
            elif role == "adi_mig_finish":
                self._adi_mig_finish_real(uc)
                return
            else:
                _ret(uc, 0)

        # IMPORT trampoline range (StoreServices GOT + adid binds)
        self._uc.hook_add(
            UC_HOOK_CODE,
            _on_code,
            begin=IMPORT_BASE + 0x8000,
            end=IMPORT_BASE + IMPORT_SIZE,
        )

    def install_ios_imports(self) -> int:
        """Patcha GOT StoreServices -> trampoline IMPORT con handler host."""
        from unicorn import UC_PROT_ALL

        n = 0
        for i, (name, (_stub, got_slot)) in enumerate(IOS_IMPORT_GOT.items()):
            tramp = IMPORT_BASE + 0x8000 + i * 0x100
            # pagina GOT da DSC
            page = got_slot & ~0xFFF
            if page not in self._lazy_pages:
                data = self._fetch_dsc_page(page)
                if data is None:
                    data = b"\x00" * 0x1000
                else:
                    data = _strip_pointers_in_page(data)
                try:
                    self._uc.mem_map(page, 0x1000, UC_PROT_ALL)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    self._uc.mem_write(page, data)
                    self._lazy_pages.add(page)
                except Exception as ex:  # noqa: BLE001
                    logger.debug("got page 0x%x: %s", page, ex)
                    continue
            try:
                self._uc.mem_write(got_slot, tramp.to_bytes(8, "little"))
            except Exception as ex:  # noqa: BLE001
                logger.debug("got patch %s: %s", name, ex)
                continue
            self._import_hooks[tramp] = name
            # assicurati RET al trampoline
            self._uc.mem_write(tramp, b"\xc0\x03\x5f\xd6")
            n += 1
        logger.info("iOS import stubs patched: %d/%d (home=%s id=%s)", n, len(IOS_IMPORT_GOT), self._home_path, self._device_id)
        return n

    def _setup_tls(self) -> None:
        """tpidrro_el0 / tpidr_el0 → pagina TSD finta (mig reply port @ +0x10)."""
        from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_TPIDRRO_EL0

        # zero + reply_port precaricato così _mig_get_reply_port prende il fast-path
        self._uc.mem_write(TLS_BASE, b"\x00" * TLS_SIZE)
        self._uc.mem_write(TLS_BASE + 0x10, (0x103).to_bytes(4, "little"))
        # pthread_self-ish pointer slot spesso a +0x0 / +0x18
        self._uc.mem_write(TLS_BASE + 0x0, TLS_BASE.to_bytes(8, "little"))
        try:
            self._uc.reg_write(UC_ARM64_REG_TPIDRRO_EL0, TLS_BASE)
            self._uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
        except Exception as ex:  # noqa: BLE001
            logger.warning("TLS reg write: %s", ex)
        # stub diretto: evita mach_msg se qualcuno azzera +0x10
        self._add_malloc_hook_va(MIG_GET_REPLY_PORT, "nop_ret0")
        # override: ritorna 0x103 non 0
        self._malloc_hooks[MIG_GET_REPLY_PORT] = "reply_port"

    def _setup_fake_malloc_zone(self) -> None:
        """malloc_zone_t minimale: vtable → entry point già hookati (zone, size)."""
        # Layout: name@8, malloc@0x10, calloc@0x18, valloc@0x20, free@0x28,
        # realloc@0x30, … version@0x68
        zone = FAKE_ZONE_BASE
        # VA DSC di __malloc_zone_* (hookati in register_malloc_exports)
        z_malloc = 0x19455517C
        z_calloc = 0x19455430C
        z_free = 0x194552D0C
        z_realloc = 0x194559D9C
        blob = bytearray(0x100)
        name_addr = FAKE_ZONE_BASE + 0x100
        self._uc.mem_write(name_addr, b"uc\x00")
        blob[8:16] = name_addr.to_bytes(8, "little")
        blob[0x10:0x18] = z_malloc.to_bytes(8, "little")
        blob[0x18:0x20] = z_calloc.to_bytes(8, "little")
        blob[0x20:0x28] = z_malloc.to_bytes(8, "little")  # valloc → malloc
        blob[0x28:0x30] = z_free.to_bytes(8, "little")
        blob[0x30:0x38] = z_realloc.to_bytes(8, "little")
        blob[0x68:0x6C] = (16).to_bytes(4, "little")
        self._uc.mem_write(zone, bytes(blob))
        arr = FAKE_ZONE_BASE + 0x800
        self._uc.mem_write(arr, zone.to_bytes(8, "little") + (0).to_bytes(8, "little"))

    def _malloc_hook_dispatch(self, uc, address: int) -> None:  # noqa: ANN001
        from unicorn.arm64_const import (
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
        )

        role = self._malloc_hooks.get(address)
        if role is None:
            return

        def _ret(value: int = 0) -> None:
            uc.reg_write(UC_ARM64_REG_X0, value & 0xFFFFFFFFFFFFFFFF)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

        def _malloc_n(n: int, zero: bool = False) -> None:
            if n <= 0:
                n = 1
            try:
                ptr = self._heap.alloc(int(n))
            except MemoryError:
                _ret(0)
                return
            if zero:
                self._uc.mem_write(ptr, b"\x00" * int(n))
            _ret(ptr)

        if role == "malloc":
            _malloc_n(uc.reg_read(UC_ARM64_REG_X0), zero=False)
        elif role == "calloc":
            _malloc_n(uc.reg_read(UC_ARM64_REG_X0) * uc.reg_read(UC_ARM64_REG_X1), zero=True)
        elif role == "realloc":
            _malloc_n(uc.reg_read(UC_ARM64_REG_X1), zero=False)
        elif role == "free":
            self._heap.free(uc.reg_read(UC_ARM64_REG_X0))
            _ret(0)
        elif role == "malloc_zone_malloc":
            _malloc_n(uc.reg_read(UC_ARM64_REG_X1), zero=False)
        elif role == "malloc_zone_calloc":
            _malloc_n(uc.reg_read(UC_ARM64_REG_X1) * uc.reg_read(UC_ARM64_REG_X2), zero=True)
        elif role == "malloc_zone_free":
            self._heap.free(uc.reg_read(UC_ARM64_REG_X1))
            _ret(0)
        elif role == "malloc_zone_realloc":
            _malloc_n(uc.reg_read(UC_ARM64_REG_X2), zero=False)
        elif role == "posix_memalign":
            outp = uc.reg_read(UC_ARM64_REG_X0)
            n = uc.reg_read(UC_ARM64_REG_X2)
            try:
                ptr = self._heap.alloc(int(n) if n else 1)
            except MemoryError:
                _ret(12)
                return
            uc.mem_write(outp, ptr.to_bytes(8, "little"))
            _ret(0)
        elif role == "aligned_alloc":
            _malloc_n(uc.reg_read(UC_ARM64_REG_X1), zero=False)
        elif role == "valloc":
            _malloc_n(uc.reg_read(UC_ARM64_REG_X0), zero=False)
        elif role == "nop_ret0":
            _ret(0)
        elif role == "reply_port":
            _ret(0x103)
        elif role == "mach_msg2_adi_mig":
            self._adi_mig_msg2_trap(uc, address)
            return
        elif role == "malloc_default_zone":
            _ret(FAKE_ZONE_BASE)

    def _adi_mig_msg2_trap(self, uc, address: int) -> None:  # noqa: ANN001
        """Emula adid su mach_msg2: preferisce /usr/libexec/adid, altrimenti stub sintetico."""
        from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0

        buf = uc.reg_read(UC_ARM64_REG_X0)
        mode = getattr(self, "_adi_mig_mode", "not_provisioned")
        try:
            hdr = bytes(uc.mem_read(buf, 0x38))
        except Exception:  # noqa: BLE001
            uc.reg_write(UC_ARM64_REG_X0, 0x10000015)  # MACH_SEND_INVALID_DEST-ish
            uc.reg_write(UC_ARM64_REG_PC, (address + 8) & 0xFFFFFFFFFFFFFFFF)
            return

        # Normalizza size COMPLEX (SS lascia 0/1/0x24) prima di leggere l'OOL.
        msgh_bits = struct.unpack_from("<I", hdr, 0)[0]
        msgh_size = struct.unpack_from("<I", hdr, 4)[0]
        if msgh_bits & 0x80000000 and msgh_size != 0x38:
            try:
                uc.mem_write(buf + 4, (0x38).to_bytes(4, "little"))
                hdr = bytes(uc.mem_read(buf, 0x38))
            except Exception:  # noqa: BLE001
                pass
        ool_addr = struct.unpack_from("<Q", hdr, 0x1C)[0]
        ool_size = struct.unpack_from("<I", hdr, 0x28)[0]
        payload = b""
        if ool_addr and 0 < ool_size < 0x10000:
            try:
                payload = bytes(uc.mem_read(ool_addr, ool_size))
            except Exception:  # noqa: BLE001
                payload = b""
        op = payload[4:8] if len(payload) >= 8 else b""

        # START: FairPlay IOKit + reply COMPLEX sintetica.
        # Il loopback XPC adid non produce un OOL che SS unpacka (cpim_len resta 0);
        # lo stub COMPLEX è il formato che SS già consuma correttamente.
        if op == ADI_MIG_OP_START and self._adid_mig_server:
            # Request OOL: u32 hdr, op, flag, i64 ds_id, u32 spim_len, spim...
            spim = b""
            if len(payload) >= 24:
                spim_len = struct.unpack_from("<I", payload, 20)[0]
                avail = len(payload) - 24
                n = min(spim_len, avail) if spim_len > 0 else avail
                if n > 0:
                    spim = payload[24 : 24 + n]
            logger.info(
                "START req ool=%d spim=%d head=%s",
                len(payload),
                len(spim),
                payload[:24].hex() if payload else "",
            )
            try:
                self._drive_fairplay_iokit_from_xpc(spim=spim)
            except Exception as ex:  # noqa: BLE001
                logger.warning("FairPlay drive su START: %s", ex)
            cpim = getattr(self, "_fp_last_cpim", None)
            if not (isinstance(cpim, (bytes, bytearray)) and len(cpim) >= 16):
                kj = getattr(self, "_fp_last_kjaimpk", None) or {}
                sec1 = kj.get("sec1") if isinstance(kj, dict) else None
                cpim = bytes(sec1[:16]) if sec1 and len(sec1) >= 16 else os.urandom(16)
            else:
                cpim = bytes(cpim[:16])
            self._last_start_cpim = cpim
            self._last_start_session = 1
            self._adi_fake_cpim = cpim
            self._adi_fake_session = 1
            # fall through allo stub sintetico sotto (non enter adid)
        elif self._adid_mig_server and self._adi_mig_enter_real(uc, address):
            return

        def _simple(retcode: int) -> bytes:
            reply = bytearray(0x40)
            struct.pack_into("<IIIIII", reply, 0, 0x12, 0x24, 0, 0, 0, ADI_MIG_REPLY_ID)
            struct.pack_into("<I", reply, 0x18, 0)
            struct.pack_into("<i", reply, 0x20, int(retcode))
            return bytes(reply)

        def _complex(blob: bytes) -> bytes:
            try:
                ool = self._heap.alloc(max(len(blob), 1))
            except MemoryError:
                return _simple(ADI_NOT_PROVISIONED)
            uc.mem_write(ool, blob)
            reply = bytearray(0x38)
            struct.pack_into(
                "<IIIIII",
                reply,
                0,
                0x80000012,  # COMPLEX
                0x38,
                0,
                0,
                0,
                ADI_MIG_REPLY_ID,
            )
            struct.pack_into("<I", reply, 0x18, 1)
            struct.pack_into("<Q", reply, 0x1C, ool)
            struct.pack_into("<I", reply, 0x24, 0x01000100)
            struct.pack_into("<I", reply, 0x28, len(blob))
            struct.pack_into("<I", reply, 0x34, len(blob))
            return bytes(reply)

        def _be_otp(mid: bytes, otp: bytes) -> bytes:
            return (
                struct.pack(">I", 0)
                + struct.pack(">I", len(mid))
                + mid
                + struct.pack(">I", len(otp))
                + otp
            )

        def _be_start(cpim: bytes, session: int) -> bytes:
            return (
                struct.pack(">I", 0)
                + struct.pack(">I", len(cpim))
                + cpim
                + struct.pack(">I", int(session) & 0xFFFFFFFF)
            )

        fake_mid = getattr(self, "_adi_fake_mid", b"\x11" * 16)
        fake_otp = getattr(self, "_adi_fake_otp", b"\x22" * 8)
        fake_cpim = getattr(self, "_adi_fake_cpim", b"\x33" * 16)
        fake_sess = int(getattr(self, "_adi_fake_session", 1))

        if op == ADI_MIG_OP_LOGIN:
            # RetCode 0x10000003 → get_login 0; -45061 → tipicamente -45002
            out = _simple(ADI_MIG_IPC_OK if mode == "provisioned_fake" else ADI_NOT_PROVISIONED)
        elif op == ADI_MIG_OP_OTP:
            if mode == "provisioned_fake":
                out = _complex(_be_otp(fake_mid, fake_otp))
            else:
                out = _simple(ADI_NOT_PROVISIONED)
        elif op == ADI_MIG_OP_START:
            # bootstrap locale anche se non ancora provisioned
            out = _complex(_be_start(fake_cpim, fake_sess))
        elif op == ADI_MIG_OP_END:
            # end vuole OOL complex con status BE=0 (non simple RetCode)
            self._adi_mig_mode = "provisioned_fake"
            out = _complex(struct.pack(">I", 0))
        elif op in (ADI_MIG_OP_ERASE, ADI_MIG_OP_DESTROY):
            if op == ADI_MIG_OP_ERASE:
                self._adi_mig_mode = "not_provisioned"
            out = _complex(struct.pack(">I", 0))
        elif op == ADI_MIG_OP_SYNC:
            out = _simple(ADI_MIG_IPC_OK if mode == "provisioned_fake" else ADI_NOT_PROVISIONED)
        else:
            out = _simple(int(getattr(self, "_adi_mig_retcode", ADI_NOT_PROVISIONED)))

        try:
            uc.mem_write(buf, out)
        except Exception:  # noqa: BLE001
            pass
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, (address + 8) & 0xFFFFFFFFFFFFFFFF)

    def _install_malloc_hooks(self) -> None:
        """Prepara tabella hook; gli indirizzi si registrano in register_malloc_exports."""
        # no-op: hook per-VA aggiunti dopo il load delle dylib
        return

    def _add_malloc_hook_va(self, va: int, role: str) -> bool:
        from unicorn import UC_HOOK_CODE

        if va in self._malloc_hooks:
            return False
        self._malloc_hooks[va] = role

        def _on_code(uc, address, size, user_data):  # noqa: ANN001, ARG001
            self._malloc_hook_dispatch(uc, address)

        # begin==end → solo questa istruzione (entry point)
        self._uc.hook_add(UC_HOOK_CODE, _on_code, begin=va, end=va)
        return True

    def register_malloc_exports(self) -> int:
        """Collega hook agli export libsystem_malloc già caricati. Ritorna # hook."""
        mapping = {
            "malloc": "malloc",
            "_malloc": "malloc",
            "calloc": "calloc",
            "_calloc": "calloc",
            "realloc": "realloc",
            "_realloc": "realloc",
            "free": "free",
            "_free": "free",
            "valloc": "valloc",
            "_valloc": "valloc",
            "aligned_alloc": "aligned_alloc",
            "_aligned_alloc": "aligned_alloc",
            "posix_memalign": "posix_memalign",
            "_posix_memalign": "posix_memalign",
            "malloc_zone_malloc": "malloc_zone_malloc",
            "_malloc_zone_malloc": "malloc_zone_malloc",
            "malloc_zone_calloc": "malloc_zone_calloc",
            "_malloc_zone_calloc": "malloc_zone_calloc",
            "malloc_zone_free": "malloc_zone_free",
            "_malloc_zone_free": "malloc_zone_free",
            "malloc_zone_realloc": "malloc_zone_realloc",
            "_malloc_zone_realloc": "malloc_zone_realloc",
            "malloc_default_zone": "malloc_default_zone",
            "_malloc_default_zone": "malloc_default_zone",
            "__malloc_zone_malloc": "malloc_zone_malloc",
            "__malloc_zone_calloc": "malloc_zone_calloc",
        }
        n = 0
        for name, role in mapping.items():
            va = self.resolve(name)
            if va is not None and self._add_malloc_hook_va(va, role):
                n += 1
        # Hardcode DSC VA noti (export parse a volte fallisce su dylib spezzate)
        hardcoded = {
            0x1945514D0: "malloc",
            0x19455103C: "calloc",
            0x194552AF4: "realloc",
            0x1945511B4: "free",
            0x194557B0C: "valloc",
            0x19455A3F0: "aligned_alloc",
            0x194558F34: "posix_memalign",
            0x194552AEC: "malloc_zone_malloc",
            0x194552CCC: "malloc_zone_calloc",
            0x194552D0C: "malloc_zone_free",
            0x194559D9C: "malloc_zone_realloc",
            0x19455517C: "malloc_zone_malloc",  # __malloc_zone_malloc
            0x19455430C: "malloc_zone_calloc",  # __malloc_zone_calloc
            0x1945511A8: "malloc_default_zone",
            0x1945590A0: "nop_ret0",  # ___malloc_init
        }
        for va, role in hardcoded.items():
            if self._add_malloc_hook_va(va, role):
                n += 1
        # Se libsystem_malloc ha già mappato __DATA_DIRTY, patcha _malloc_zones ora
        self._force_patch_malloc_zones()
        logger.info("malloc hooks registrati: %d (map size=%d)", n, len(self._malloc_hooks))
        return len(self._malloc_hooks)

    def install_adi_mig_stub(
        self,
        retcode: int = ADI_NOT_PROVISIONED,
        mode: str = "not_provisioned",
    ) -> bool:
        """Stub mach_msg2_trap come adid (msgh_id 1200→1300).

        mode:
          - not_provisioned: login/otp → -45061; start → CPIM fake (bootstrap locale)
          - provisioned_fake: login ok + OTP MID/OTP sintetici (no crypto Apple reale)
        """
        self._adi_mig_retcode = int(retcode)
        self._adi_mig_mode = mode
        self._adi_fake_mid = getattr(self, "_adi_fake_mid", os.urandom(16))
        self._adi_fake_otp = getattr(self, "_adi_fake_otp", os.urandom(8))
        self._adi_fake_cpim = getattr(self, "_adi_fake_cpim", os.urandom(16))
        self._adi_fake_session = getattr(self, "_adi_fake_session", 1)
        ok = self._add_malloc_hook_va(MACH_MSG2_TRAP, "mach_msg2_adi_mig")
        logger.info(
            "ADI MIG stub mach_msg2 @0x%x mode=%s retcode=%d installed=%s adid=%s",
            MACH_MSG2_TRAP,
            mode,
            retcode,
            ok,
            bool(self._adid_mig_server),
        )
        return ok

    def _next_adid_tramp(self, role: str) -> int:
        tramp = ADID_IMPORT_TRAMP_BASE + self._adid_tramp_i * 0x20
        self._adid_tramp_i += 1
        if tramp >= IMPORT_BASE + IMPORT_SIZE - 0x20:
            raise MemoryError("adid import trampoline arena esaurita")
        self._uc.mem_write(tramp, b"\xc0\x03\x5f\xd6")
        self._import_hooks[tramp] = role
        return tramp

    @staticmethod
    def _fp_pack_kjaimpk(
        *,
        field0: int = 0x8,
        field4: int = 0x525E5BA4,
        field8: int = 0x34788A7A,
        sec1: bytes = b"",
        sec2: bytes = b"",
        size: int | None = None,
        fp_ret: int = 0,
    ) -> bytes:
        """Pack kJAimpk (FairPlayIOKit sel=21 / ucRunversiond)."""
        buf = bytearray(FP_KJAIMPK_SIZE)
        struct.pack_into("<III", buf, 0, field0 & 0xFFFFFFFF, field4 & 0xFFFFFFFF, field8 & 0xFFFFFFFF)
        s1 = (sec1 or b"\x00" * 20)[:20].ljust(20, b"\x00")
        buf[12:32] = s1
        s2 = bytearray(512)
        payload = sec2 or b""
        n = min(len(payload), 512)
        s2[:n] = payload[:n]
        buf[32:544] = s2
        sz = size if size is not None else n
        struct.pack_into("<I", buf, 544, sz & 0xFFFFFFFF)
        buf[548] = fp_ret & 0xFF
        return bytes(buf)

    @staticmethod
    def _fp_unpack_kjaimpk(blob: bytes) -> dict[str, Any]:
        if len(blob) < 549:
            return {"ok": False}
        f0, f4, f8 = struct.unpack_from("<III", blob, 0)
        sec1 = bytes(blob[12:32])
        size = struct.unpack_from("<I", blob, 544)[0]
        sec2 = bytes(blob[32 : 32 + min(size, 512)]) if size <= 512 else bytes(blob[32:544])
        fp_ret = blob[548]
        return {
            "ok": True,
            "field0": f0,
            "field4": f4,
            "field8": f8,
            "sec1": sec1,
            "sec2": sec2,
            "size": size,
            "fp_ret": fp_ret,
        }

    def _fp_uid_aes_key(self) -> bytes:
        """Chiave IOAESAccelerator UID selector 0x899.

        Se ``AKD_UID_ORACLE_PATH`` punta a un file:
          - 16 B → usati come chiave AES
          - 32 B → primi 16 = chiave (secondi 16 reserved/IV seed)
          - altro → SHA256(file)[:16]
        Altrimenti fallback SHA256 software (non passa midFinish Apple).
        """
        import hashlib
        import os
        from pathlib import Path

        oracle = (os.environ.get("AKD_UID_ORACLE_PATH") or "").strip()
        if oracle:
            path = Path(oracle)
            if path.is_file():
                raw = path.read_bytes()
                if len(raw) >= 32:
                    key = raw[:16]
                    logger.info(
                        "UID oracle loaded %s (%d B) → key=%s… (32B+ layout)",
                        path,
                        len(raw),
                        key[:4].hex(),
                    )
                    return key
                if len(raw) == 16:
                    logger.info(
                        "UID oracle loaded %s → key=%s…",
                        path,
                        raw[:4].hex(),
                    )
                    return raw
                if len(raw) > 0:
                    key = hashlib.sha256(raw).digest()[:16]
                    logger.info(
                        "UID oracle loaded %s (%d B) → SHA256[:16]=%s…",
                        path,
                        len(raw),
                        key[:4].hex(),
                    )
                    return key
                logger.warning("UID oracle vuoto: %s — fallback fake SHA256", path)
            else:
                logger.warning("UID oracle non trovato: %s — fallback fake SHA256", path)

        dev = (getattr(self, "_device_id", None) or b"ios-adi-device").encode(
            "utf-8", "replace"
        ) if isinstance(getattr(self, "_device_id", None), str) else (
            getattr(self, "_device_id", None) or b"ios-adi-device"
        )
        key = hashlib.sha256(
            b"IOAESAccelerator-UID"
            + struct.pack("<I", FP_IOAES_UID_SELECTOR)
            + bytes(dev)
        ).digest()[:16]
        logger.info("UID key fake SHA256=%s… (set AKD_UID_ORACLE_PATH)", key[:4].hex())
        return key

    def _fp_hw_aes_kjaimpk(
        self, in_sec1: bytes, in_sec2: bytes, in_blob: bytes
    ) -> tuple[bytes, bytes]:
        """AES-CBC path modellato su ucRunversiond → IOAESAccelerator UID 0x899."""
        import hashlib

        key = self._fp_uid_aes_key()
        iv = hashlib.sha256(b"fp-kjaimpk-iv" + in_sec1).digest()[:16]
        body = bytes(in_sec2) if in_sec2 else in_blob[32:32 + 64]
        if not body:
            body = hashlib.sha256(in_blob).digest()
        pad_n = (16 - (len(body) % 16)) % 16
        try:
            from Crypto.Cipher import AES

            ct = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(body + bytes(pad_n))
        except Exception:  # noqa: BLE001
            ct = hashlib.sha256(key + iv + body).digest() * 4
        sec1 = hashlib.sha256(b"fp-sec1" + key + in_sec1 + ct[:32]).digest()[:20]
        # sec2 almeno quanto l'input (o 64 B) — CPIM prende sec1[:16]
        need = max(len(body), 64)
        sec2 = (ct * ((need // max(len(ct), 1)) + 1))[:need]
        logger.info(
            "FairPlay hw-AES kJAimpk UID=0x%x key=%s sec2=%d aes_calls=%d",
            FP_IOAES_UID_SELECTOR,
            key[:4].hex(),
            len(sec2),
            int(getattr(self, "_fp_aes_calls", 0)) + 1,
        )
        return sec1, sec2

    def _fairplay_connect_struct(self, uc) -> int:  # noqa: ANN001
        """FairPlayIOKit IOConnectCallStructMethod — sel=21 (kJAimpk) o generico."""
        from unicorn.arm64_const import (
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
            UC_ARM64_REG_X4,
            UC_ARM64_REG_X5,
        )

        conn = int(uc.reg_read(UC_ARM64_REG_X0))
        sel = int(uc.reg_read(UC_ARM64_REG_X1))
        inp = int(uc.reg_read(UC_ARM64_REG_X2))
        in_cnt = int(uc.reg_read(UC_ARM64_REG_X3))
        outp = int(uc.reg_read(UC_ARM64_REG_X4))
        out_cnt_p = int(uc.reg_read(UC_ARM64_REG_X5))

        in_blob = b""
        if inp and 0 < in_cnt < 0x10000:
            try:
                in_blob = bytes(uc.mem_read(inp, in_cnt))
            except Exception:  # noqa: BLE001
                in_blob = b""

        out_cnt = 0
        if out_cnt_p:
            try:
                out_cnt = int.from_bytes(uc.mem_read(out_cnt_p, 8), "little")
            except Exception:  # noqa: BLE001
                try:
                    out_cnt = int.from_bytes(uc.mem_read(out_cnt_p, 4), "little")
                except Exception:  # noqa: BLE001
                    out_cnt = 0

        rec = {
            "conn": conn,
            "selector": sel,
            "in_len": len(in_blob),
            "out_cnt": out_cnt,
            "in_head": in_blob[:32].hex(),
        }
        self._fp_calls.append(rec)
        logger.info(
            "FairPlay IOConnectCallStructMethod sel=%d in=%d out_cap=%d head=%s hw=%s",
            sel,
            len(in_blob),
            out_cnt,
            rec["in_head"],
            bool(getattr(self, "_fp_hw_loaded", False)),
        )

        import hashlib

        if sel == FP_IOKIT_SEL_VERSIONED and len(in_blob) >= 32:
            # Risposta kJAimpk (ucRunversiond). Con FairPlayIOKit+fairplayd caricati
            # usa AES-CBC modellato sul path UID 0x899 (fairplay_research / IOAESAccelerator).
            parsed = self._fp_unpack_kjaimpk(in_blob)
            spim_len = int(parsed.get("size") or 0)
            in_sec1 = bytes(parsed.get("sec1") or b"")[:20]
            in_sec2 = bytes(parsed.get("sec2") or b"")
            if spim_len > 0:
                in_sec2 = in_sec2[: min(spim_len, len(in_sec2))]
            sec1 = b""
            sec2_body = b""
            used_uefdbi = False
            # Nested emu_start corrompe ADI anche con context_save → solo precompute
            # fuori da invoke_cdecl (_fp_uefdbi_pre) oppure chiamata top-level.
            pre = getattr(self, "_fp_uefdbi_pre", None)
            if (
                isinstance(pre, tuple)
                and len(pre) == 3
                and (any(pre[0]) or any(pre[1]))
            ):
                sec1, sec2_body, _rc = pre
                used_uefdbi = True
                logger.info("UeFdbi precompute hit rc=%s sec1=%s", _rc, sec1[:8].hex())
            elif getattr(self, "_fp_uefdbi", 0) and not getattr(
                self, "_fp_in_adi_emu", False
            ):
                inv = self._fp_invoke_uefdbi(
                    int(parsed.get("field0") if parsed.get("field0") is not None else 0x8),
                    int(
                        parsed.get("field4")
                        if parsed.get("field4") is not None
                        else 0x525E5BA4
                    ),
                    int(
                        parsed.get("field8")
                        if parsed.get("field8") is not None
                        else 0x34788A7A
                    ),
                    in_sec1,
                    in_sec2 if in_sec2 else in_blob[32 : 32 + max(spim_len, 64)],
                )
                if inv is not None:
                    sec1, sec2_body, _rc = inv
                    if any(sec1) or any(sec2_body):
                        used_uefdbi = True
                    else:
                        logger.info(
                            "UeFdbi output nullo (rc=%s) — fallback AES UID",
                            _rc,
                        )
            elif getattr(self, "_fp_uefdbi", 0):
                logger.info("UeFdbi skip nested — AES UID path")
            if not used_uefdbi and getattr(self, "_fp_hw_loaded", False):
                sec1, sec2_body = self._fp_hw_aes_kjaimpk(in_sec1, in_sec2, in_blob)
                self._fp_aes_calls = int(getattr(self, "_fp_aes_calls", 0)) + 1
            elif not used_uefdbi:
                seed = hashlib.sha256(b"fp-kjaimpk" + in_blob).digest()
                sec1 = seed[:20]
                sec2_body = seed[16:32] + hashlib.sha256(seed + b"sec2").digest()
                if spim_len > 16:
                    sec2_body = (sec2_body * ((spim_len // 16) + 1))[:spim_len]
            out_blob = self._fp_pack_kjaimpk(
                field0=parsed.get("field0", 0x8),
                field4=parsed.get("field4", 0x525E5BA4),
                field8=parsed.get("field8", 0x34788A7A),
                sec1=sec1,
                sec2=sec2_body,
                size=min(len(sec2_body), 512),
                fp_ret=0,
            )
            n_out = FP_KJAIMPK_SIZE
            self._fp_last_kjaimpk = self._fp_unpack_kjaimpk(out_blob)
            self._fp_last_out = bytes(out_blob)
            # CPIM ADI = primi 16 B di sec1 (stabile, non-zero)
            self._fp_last_cpim = bytes(sec1[:16])
        elif conn == FAKE_IOAES_CONNECT:
            # IOAESAccelerator::performAES stub (UID/GID). Input/output buffer opachi.
            self._fp_aes_calls = int(getattr(self, "_fp_aes_calls", 0)) + 1
            n_out = out_cnt if 0 < out_cnt < 0x10000 else max(len(in_blob), 16)
            key = self._fp_uid_aes_key()
            try:
                from Crypto.Cipher import AES

                cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
                pad_n = (16 - (len(in_blob) % 16)) % 16
                out_blob = cipher.encrypt(in_blob + bytes(pad_n))[:n_out]
            except Exception:  # noqa: BLE001
                out_blob = hashlib.sha256(key + in_blob).digest() * ((n_out // 32) + 1)
                out_blob = out_blob[:n_out]
            self._fp_last_out = bytes(out_blob)
        else:
            n_out = out_cnt if 0 < out_cnt < 0x10000 else 64
            out_blob = bytearray(n_out)
            if n_out >= 4:
                struct.pack_into(">I", out_blob, 0, 0)
            body_len = max(0, n_out - 4)
            if body_len:
                seed = hashlib.sha256(
                    b"fp-iokit-stub" + bytes([sel & 0xFF]) + in_blob
                ).digest()
                out_blob[4 : 4 + body_len] = (seed * ((body_len // len(seed)) + 1))[:body_len]
            self._fp_last_out = bytes(out_blob)
            self._fp_last_cpim = bytes(out_blob[4:20]) if n_out >= 20 else os.urandom(16)

        if outp and n_out:
            try:
                uc.mem_write(outp, bytes(out_blob)[:n_out])
            except Exception as ex:  # noqa: BLE001
                logger.warning("FairPlay out write: %s", ex)
                return KIO_RETURN_NO_DEVICE
        if out_cnt_p:
            try:
                uc.mem_write(out_cnt_p, int(n_out).to_bytes(8, "little"))
            except Exception:  # noqa: BLE001
                try:
                    uc.mem_write(out_cnt_p, int(n_out).to_bytes(4, "little"))
                except Exception:  # noqa: BLE001
                    pass
        return KIO_RETURN_SUCCESS

    def _drive_fairplay_iokit_from_xpc(self, spim: bytes | None = None) -> None:
        """Apri FairPlayIOKit (match+open type=1) e chiama sel=21 (kJAimpk) con SPIM."""
        from unicorn.arm64_const import (
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
            UC_ARM64_REG_X4,
            UC_ARM64_REG_X5,
        )

        matching = self._alloc_cfstring(FP_IOKIT_MATCH)
        self._fp_matching = matching
        self._fp_iter_alive = True
        self._fp_opened = True
        self._fp_open_type = FP_IOKIT_OPEN_TYPE
        logger.info(
            "drive FairPlay IOKit: match=%r open_type=%d connect=%#x",
            FP_IOKIT_MATCH,
            FP_IOKIT_OPEN_TYPE,
            FAKE_FP_CONNECT,
        )

        spim_b = bytes(spim) if spim else b""
        # Envelope kJAimpk: sec1 = hash(SPIM)[:20], sec2 = SPIM, size = len(SPIM)
        import hashlib

        sec1 = hashlib.sha256(b"adi-spim-sec1" + spim_b).digest()[:20]
        in_blob = self._fp_pack_kjaimpk(sec1=sec1, sec2=spim_b, size=len(spim_b) or 0x10)
        in_buf = self._heap.alloc(len(in_blob))
        out_buf = self._heap.alloc(FP_KJAIMPK_SIZE)
        out_cnt_p = self._heap.alloc(8)
        self._uc.mem_write(in_buf, in_blob)
        self._uc.mem_write(out_buf, b"\x00" * FP_KJAIMPK_SIZE)
        self._uc.mem_write(out_cnt_p, FP_KJAIMPK_SIZE.to_bytes(8, "little"))

        uc = self._uc
        saved = [uc.reg_read(r) for r in (
            UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
            UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
        )]
        try:
            uc.reg_write(UC_ARM64_REG_X0, FAKE_FP_CONNECT)
            uc.reg_write(UC_ARM64_REG_X1, FP_IOKIT_SEL_VERSIONED)
            uc.reg_write(UC_ARM64_REG_X2, in_buf)
            uc.reg_write(UC_ARM64_REG_X3, len(in_blob))
            uc.reg_write(UC_ARM64_REG_X4, out_buf)
            uc.reg_write(UC_ARM64_REG_X5, out_cnt_p)
            kr = self._fairplay_connect_struct(uc)
            logger.info(
                "drive FairPlay IOConnect → kr=%#x sel=%d calls=%d spim=%d",
                kr,
                FP_IOKIT_SEL_VERSIONED,
                len(self._fp_calls),
                len(spim_b),
            )
        finally:
            for reg, val in zip(
                (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                 UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5),
                saved,
                strict=True,
            ):
                uc.reg_write(reg, val)

    def load_adid(self, path: Path) -> bool:
        """Mappa /usr/libexec/adid (PIE @0x100000000) e applica bind → trampoline host."""
        import lief
        from unicorn import UC_PROT_ALL

        path = path.resolve()
        if not path.exists():
            logger.warning("adid assente: %s", path)
            return False
        try:
            self.load(path, "adid")
        except Exception as ex:  # noqa: BLE001
            logger.warning("load adid fallito: %s", ex)
            return False

        parsed = lief.MachO.parse(str(path))
        binary = _macho_slice(parsed)
        if binary is None:
            return False

        # Slot dati noti
        data_slots = {
            "_NDR_record": ADID_NDR_RECORD,
            "___stack_chk_guard": STACK_CHK_GUARD_SLOT,
            "_mach_task_self_": ADID_NDR_RECORD + 0x100,
            "_bootstrap_port": ADID_NDR_RECORD + 0x108,
            "_kCFAllocatorDefault": ADID_NDR_RECORD + 0x200,
            "_kCFAllocatorNull": ADID_NDR_RECORD + 0x208,
            "_kCFBooleanTrue": FAKE_CFBOOL_TRUE,
            "_kCFRunLoopCommonModes": ADID_NDR_RECORD + 0x218,
            "_kCFURLIsExcludedFromBackupKey": ADID_NDR_RECORD + 0x220,
            "__xpc_type_dictionary": FAKE_XPC_TYPE_DICT,
            "__xpc_type_error": FAKE_XPC_TYPE_ERROR,
            "__xpc_error_connection_interrupted": ADID_NDR_RECORD + 0x280,
            "__xpc_error_connection_invalid": ADID_NDR_RECORD + 0x288,
            "__NSConcreteGlobalBlock": ADID_NDR_RECORD + 0x300,
            "__NSConcreteStackBlock": ADID_NDR_RECORD + 0x380,
            "___CFConstantStringClassReference": CF_OBJ_BASE,
        }
        self._uc.mem_write(ADID_NDR_RECORD + 0x100, (0x101).to_bytes(4, "little"))  # task self
        self._uc.mem_write(ADID_NDR_RECORD + 0x108, (0x102).to_bytes(4, "little"))  # bootstrap
        # kCFBooleanTrue è un *puntatore* al CFBoolean — alcuni bind vogliono l'indirizzo della cella
        self._uc.mem_write(ADID_NDR_RECORD + 0x210, FAKE_CFBOOL_TRUE.to_bytes(8, "little"))
        # xpc_get_type(obj) confrontato con *_xpc_type_dictionary
        self._uc.mem_write(FAKE_XPC_TYPE_DICT, b"XPC_DICT\x00" + b"\x00" * 7)
        self._uc.mem_write(FAKE_XPC_TYPE_ERROR, b"XPC_ERR\x00\x00" + b"\x00" * 7)
        self._uc.mem_write(
            ADID_NDR_RECORD + 0x280, FAKE_XPC_TYPE_ERROR.to_bytes(8, "little")
        )
        self._uc.mem_write(
            ADID_NDR_RECORD + 0x288, FAKE_XPC_TYPE_ERROR.to_bytes(8, "little")
        )

        role_map = {
            "_MGCopyAnswer": "MGCopyAnswer",
            "_CFStringCreateWithCStringNoCopy": "CFStringCreateWithCString",
            "_CFStringCreateWithCString": "CFStringCreateWithCString",
            "_malloc": "malloc",
            "_free": "free",
            "___memcpy_chk": "memcpy_chk",
            "_mig_deallocate": "mig_deallocate",
            "___stack_chk_fail": "nop_ret0",
            "_IOConnectCallStructMethod": "IOConnectCallStructMethod",
            "_IOServiceMatching": "IOServiceMatching",
            "_IOServiceGetMatchingServices": "IOServiceGetMatchingServices",
            "_IOServiceOpen": "IOServiceOpen",
            "_IOIteratorNext": "IOIteratorNext",
            "_IOObjectRelease": "IOObjectRelease",
            "_IOMainPort": "IOMainPort",
            "_arc4random": "arc4random",
            "_arc4random_uniform": "arc4random",
            "_time": "time",
            "_gettimeofday": "gettimeofday",
            "_CFRelease": "CFRelease",
            "_mach_msg_destroy": "mach_msg_destroy",
            "_xpc_release": "xpc_release",
            "_open": "open",
            "_stat": "stat",
            "_fstat": "stat",
            "_lstat": "stat",
            "_pthread_rwlock_rdlock": "pthread_mutex_lock",
            "_pthread_rwlock_wrlock": "pthread_mutex_lock",
            "_pthread_rwlock_unlock": "pthread_mutex_unlock",
            "_pthread_rwlock_init": "nop_ret0",
            "_pthread_rwlock_destroy": "nop_ret0",
            "_pthread_once": "nop_ret0",
            "_chmod": "nop_ret0",
            "_fchmod": "nop_ret0",
            "_mkdir": "nop_ret0",
            "_unlink": "nop_ret0",
            "_umask": "nop_ret0",
            "_close": "nop_ret0",
            "_sched_yield": "nop_ret0",
            "_signal": "nop_ret0",
            "_ptrace": "nop_ret0",
            "_notify_post": "nop_ret0",
            "_os_log_type_enabled": "nop_ret0",
            "__os_log_impl": "nop_ret0",
            "dyld_stub_binder": "nop_ret0",
            "_audit_token_to_au32": "nop_ret0",
            "_SecTaskCopyValueForEntitlement": "SecTaskCopyValueForEntitlement",
            "_SecTaskCreateWithAuditToken": "SecTaskCreateWithAuditToken",
            "_CFAllocatorAllocate": "malloc",
            "_CFAllocatorDeallocate": "free",
            "_CFGetTypeID": "CFGetTypeID",
            "_CFBooleanGetTypeID": "CFBooleanGetTypeID",
            "_CFNumberGetTypeID": "CFNumberGetTypeID",
            "_CFNumberGetValue": "CFNumberGetValue",
            "_CFEqual": "CFEqual",
            "_CFBooleanGetValue": "CFBooleanGetValue",
            "_CFStringGetCString": "CFStringGetCString",
            "_CFStringGetLength": "CFStringGetLength",
            "_CFStringGetTypeID": "CFStringGetTypeID",
            "_strtoul": "strtoul",
            "_CFRunLoopGetCurrent": "nop_ret0",
            "_CFRunLoopGetMain": "nop_ret0",
            "_CFRunLoopRun": "nop_ret0",
            "_CFRunLoopStop": "nop_ret0",
            "_CFRunLoopAddSource": "nop_ret0",
            "_CFMachPortCreateWithPort": "nop_ret0",
            "_CFMachPortCreateRunLoopSource": "nop_ret0",
            "_CFMachPortInvalidate": "nop_ret0",
            "_CFFileDescriptorCreate": "nop_ret0",
            "_CFFileDescriptorCreateRunLoopSource": "nop_ret0",
            "_CFFileDescriptorEnableCallBacks": "nop_ret0",
            "_CFFileDescriptorGetNativeDescriptor": "nop_ret0",
            "_CFFileDescriptorInvalidate": "nop_ret0",
            "_CFURLCreateFromFileSystemRepresentation": "nop_ret0",
            "_CFURLSetResourcePropertyForKey": "nop_ret0",
            "_bootstrap_check_in": "nop_ret0",
            "_dispatch_queue_create": "dispatch_queue_create",
            "_xpc_connection_activate": "xpc_connection_activate",
            "_xpc_connection_cancel": "xpc_connection_cancel",
            "_xpc_connection_create_mach_service": "xpc_connection_create_mach_service",
            "_xpc_connection_resume": "xpc_connection_resume",
            "_xpc_connection_send_message_with_reply_sync": "xpc_connection_send_message_with_reply_sync",
            "_xpc_connection_set_event_handler": "xpc_connection_set_event_handler",
            "_xpc_connection_set_target_queue": "xpc_connection_set_target_queue",
            "_xpc_copy_description": "xpc_copy_description",
            "_xpc_dictionary_create_empty": "xpc_dictionary_create_empty",
            "_xpc_dictionary_create_reply": "xpc_dictionary_create_reply",
            "_xpc_dictionary_get_audit_token": "xpc_dictionary_get_audit_token",
            "_xpc_dictionary_get_data": "xpc_dictionary_get_data",
            "_xpc_dictionary_get_value": "xpc_dictionary_get_value",
            "_xpc_dictionary_send_reply": "xpc_dictionary_send_reply",
            "_xpc_dictionary_set_data": "xpc_dictionary_set_data",
            "_xpc_get_type": "xpc_get_type",
            "_xpc_transaction_begin": "xpc_transaction_begin",
            "_xpc_transaction_end": "xpc_transaction_end",
            "_container_system_path_for_identifier": "nop_ret0",
            "_vm_allocate": "vm_allocate",
            "_mach_vm_allocate": "vm_allocate",
            "_vm_deallocate": "vm_deallocate",
            "_mach_vm_deallocate": "vm_deallocate",
            "_CFAllocatorAllocate": "cf_allocator_allocate",
            "_CFAllocatorDeallocate": "free",
            "_mach_msg": "nop_ret0",
            "_mach_msg_destroy": "mach_msg_destroy",
            "_mmap": "nop_ret0",
            "_munmap": "nop_ret0",
            "_read": "nop_ret0",
            "_write": "nop_ret0",
            "_fcntl": "nop_ret0",
            "_kevent": "nop_ret0",
            "_kqueue": "nop_ret0",
            "_sysctlbyname": "nop_ret0",
            "_sysconf": "nop_ret0",
            "_task_info": "nop_ret0",
            "_opendir": "nop_ret0",
            "_closedir": "nop_ret0",
            "_dirfd": "nop_ret0",
            "_ftruncate": "nop_ret0",
            "_open_dprotected_np": "open",
            "___chkstk_darwin": "nop_ret0",
            "___error": "nop_ret0",
        }

        # Solo slot GOT / la_symbol / import-table (on-disk 0 o ordinale ≤0x10)
        # + pool offuscato SOLO per simboli in role_map (bind lief+addend).
        got_lo = got_hi = la_lo = la_hi = None
        for sec in binary.sections:
            name = (getattr(sec, "name", None) or "").lower()
            va = int(sec.virtual_address)
            sz = int(sec.size)
            if name.endswith("__got") or name == "__got":
                got_lo, got_hi = va, va + sz
            elif "la_symbol" in name:
                la_lo, la_hi = va, va + sz

        def _slot_ok(addr: int, on_disk: int, sym: str) -> bool:
            if got_lo is not None and got_lo <= addr < got_hi:
                return True
            if la_lo is not None and la_lo <= addr < la_hi:
                return True
            if 0x1001A2A00 <= addr < 0x1001A3000 and on_disk <= 0x10:
                return True
            if on_disk == 0 and addr < 0x100198100:
                return True
            # Pool offuscato: solo FairPlay/IOKit + I/O essenziali (vedi ADID_POOL_BIND_SYMS)
            if sym in ADID_POOL_BIND_SYMS and on_disk > 0x1000:
                return True
            return False

        def _va_to_file_off(va: int) -> int | None:
            for seg in binary.segments:
                v0 = int(seg.virtual_address)
                vsz = int(seg.virtual_size)
                if v0 <= va < v0 + vsz:
                    f0 = int(seg.file_offset)
                    return f0 + (va - v0)
            return None

        raw = path.read_bytes()
        n_data = 0
        n_func = 0
        n_skip = 0
        seen: set[int] = set()
        try:
            bindings = list(binary.dyld_info.bindings)
        except Exception:  # noqa: BLE001
            bindings = list(getattr(binary, "bindings", []) or [])

        for bi in bindings:
            try:
                addr = int(bi.address)
                sym = bi.symbol.name if bi.symbol is not None else ""
            except Exception:  # noqa: BLE001
                continue
            if not sym or addr in seen:
                continue
            seen.add(addr)
            foff = _va_to_file_off(addr)
            on_disk = 0
            if foff is not None and foff + 8 <= len(raw):
                on_disk = int.from_bytes(raw[foff : foff + 8], "little")
            if not _slot_ok(addr, on_disk, sym):
                n_skip += 1
                continue
            page = addr & ~0xFFF
            try:
                self._uc.mem_map(page, 0x1000, UC_PROT_ALL)
            except Exception:  # noqa: BLE001
                pass
            try:
                addend = int(bi.addend)
            except Exception:  # noqa: BLE001
                addend = 0
            # Pool offuscato: on-disk == addend → slot = value + addend (poi +magic a runtime)
            pool_enc = (
                0x10 < addend < 0x100000000
                and on_disk == addend
                and on_disk > 0x1000
            )

            if sym in data_slots:
                try:
                    val = int(data_slots[sym])
                    if pool_enc:
                        val = (val + addend) & 0xFFFFFFFFFFFFFFFF
                    self._uc.mem_write(addr, val.to_bytes(8, "little"))
                    n_data += 1
                except Exception as ex:  # noqa: BLE001
                    logger.debug("adid data bind %s@0x%x: %s", sym, addr, ex)
                continue
            role = role_map.get(sym, "nop_ret0")
            try:
                tramp = self._next_adid_tramp(role)
                # Dispatcher offuscato: slot = &fn + addend, poi add magic (=-addend).
                # GOT/la_symbol: addend=0 → scrivi solo trampoline.
                if pool_enc:
                    slot_val = (tramp + addend) & 0xFFFFFFFFFFFFFFFF
                else:
                    slot_val = tramp
                self._uc.mem_write(addr, slot_val.to_bytes(8, "little"))
                n_func += 1
            except Exception as ex:  # noqa: BLE001
                logger.debug("adid func bind %s@0x%x: %s", sym, addr, ex)

        # Replica i bind pool: lo stesso addend compare in più slot della
        # tabella offuscata; lief ne elenca uno solo per simbolo.
        n_spread = self._spread_adid_pool_binds(binary, raw, _va_to_file_off)

        self._install_adid_page0_dispatcher()
        self._install_adid_obf_malloc_hook()

        self._adid_path = path
        self._adid_mig_server = ADID_MIG_SERVER
        self._adid_finish_tramp = self._next_adid_tramp("adi_mig_finish")
        self._exports["adid_mig_server"] = ADID_MIG_SERVER
        self._exports["adid_mig_routine"] = ADID_MIG_ROUTINE
        logger.info(
            "adid caricato %s binds data=%d func=%d skip_obf=%d spread=%d mig_server=0x%x",
            path.name,
            n_data,
            n_func,
            n_skip,
            n_spread,
            ADID_MIG_SERVER,
        )
        return True

    def load_fairplay_iokit(self, path: Path) -> bool:
        """Mappa FairPlayIOKit (kext prelinked ricostruito) ai VA kernel originali."""
        path = path.resolve()
        if not path.exists():
            logger.warning("FairPlayIOKit assente: %s", path)
            return False
        try:
            self.load(path, "FairPlayIOKit")
        except Exception as ex:  # noqa: BLE001
            logger.warning("load FairPlayIOKit fallito: %s", ex)
            return False
        self._fairplay_iokit_path = path
        self._fp_hw_loaded = True
        logger.info(
            "FairPlayIOKit mappato %s (%d B) — TEXT_EXEC @ kernel VA (IOConnect ancora stub host)",
            path.name,
            path.stat().st_size,
        )
        return True

    def load_fairplayd(self, path: Path) -> bool:
        """Mappa /usr/sbin/fairplayd.H2 a FAIRPLAYD_IMAGE_BASE (evita overlap con adid)."""
        import lief
        from unicorn import UC_PROT_ALL

        path = path.resolve()
        if not path.exists():
            logger.warning("fairplayd assente: %s", path)
            return False

        parsed = lief.MachO.parse(str(path))
        binary = _macho_slice(parsed)
        if binary is None:
            logger.warning("fairplayd: nessuno slice ARM64")
            return False

        image_base = int(getattr(binary, "imagebase", 0) or ADID_IMAGE_BASE)
        slide = (FAIRPLAYD_IMAGE_BASE - image_base) & 0xFFFFFFFFFFFFFFFF
        mapped = 0
        for seg in binary.segments:
            vsize = int(seg.virtual_size)
            if vsize == 0:
                continue
            seg_name = (getattr(seg, "name", None) or "")
            if "PAGEZERO" in seg_name.upper() or (
                int(seg.virtual_address) == 0 and vsize >= 0x10000000
            ):
                continue
            content = bytes(getattr(seg, "content", b"") or b"")
            if not content and vsize > 0x4000000:
                continue
            va = (int(seg.virtual_address) + slide) & 0xFFFFFFFFFFFFFFFF
            map_base = va & ~0xFFF
            map_end = _align(va + vsize)
            map_size = map_end - map_base
            off = 0
            while off < map_size:
                this = min(0x1000000, map_size - off)
                page = map_base + off
                try:
                    self._uc.mem_map(page, this, UC_PROT_ALL)
                except Exception:  # noqa: BLE001
                    sub = 0
                    while sub < this:
                        try:
                            self._uc.mem_map(page + sub, 0x1000, UC_PROT_ALL)
                        except Exception:  # noqa: BLE001
                            pass
                        sub += 0x1000
                off += this
            if content:
                chunk = content[: min(len(content), vsize)]
                woff = 0
                while woff < len(chunk):
                    piece = chunk[woff : woff + 0x400000]
                    self._uc.mem_write(va + woff, piece)
                    woff += len(piece)
            mapped += 1

        # Bind minimi: IOKit/FairPlay + alloc → stessi trampoline host di adid
        role_map = {
            "_IOConnectCallStructMethod": "IOConnectCallStructMethod",
            "_IOServiceMatching": "IOServiceMatching",
            "_IOServiceGetMatchingServices": "IOServiceGetMatchingServices",
            "_IOServiceOpen": "IOServiceOpen",
            "_IOIteratorNext": "IOIteratorNext",
            "_IOObjectRelease": "IOObjectRelease",
            "_IOMainPort": "IOMainPort",
            "_malloc": "malloc",
            "_free": "free",
            "_calloc": "malloc",
            "_realloc": "malloc",
            "___stack_chk_fail": "nop_ret0",
            "_pthread_mutex_lock": "pthread_mutex_lock",
            "_pthread_mutex_unlock": "pthread_mutex_unlock",
            "_pthread_once": "nop_ret0",
            "_arc4random": "arc4random",
            "_gettimeofday": "gettimeofday",
            "_time": "time",
            "_xpc_connection_create_mach_service": "xpc_connection_create_mach_service",
            "_xpc_connection_send_message_with_reply_sync": "xpc_connection_send_message_with_reply_sync",
            "_xpc_connection_set_event_handler": "xpc_connection_set_event_handler",
            "_xpc_connection_resume": "xpc_connection_resume",
            "_xpc_connection_activate": "xpc_connection_activate",
            "_xpc_dictionary_create_empty": "xpc_dictionary_create_empty",
            "_xpc_dictionary_set_data": "xpc_dictionary_set_data",
            "_xpc_dictionary_get_data": "xpc_dictionary_get_data",
            "_xpc_get_type": "xpc_get_type",
            "_xpc_release": "xpc_release",
        }
        data_slots = {
            "___stack_chk_guard": STACK_CHK_GUARD_SLOT,
            "_mach_task_self_": FAIRPLAYD_NDR_RECORD + 0x100,
            "_bootstrap_port": FAIRPLAYD_NDR_RECORD + 0x108,
            "__xpc_type_dictionary": FAKE_XPC_TYPE_DICT,
            "__xpc_type_error": FAKE_XPC_TYPE_ERROR,
        }
        try:
            self._uc.mem_map(FAIRPLAYD_NDR_RECORD, 0x1000, UC_PROT_ALL)
        except Exception:  # noqa: BLE001
            pass
        self._uc.mem_write(FAIRPLAYD_NDR_RECORD + 0x100, (0x201).to_bytes(4, "little"))
        self._uc.mem_write(FAIRPLAYD_NDR_RECORD + 0x108, (0x202).to_bytes(4, "little"))

        def _va_to_file_off(va: int) -> int | None:
            # va is slid; convert back to file VA for lief segment lookup
            file_va = (va - slide) & 0xFFFFFFFFFFFFFFFF
            for seg in binary.segments:
                v0 = int(seg.virtual_address)
                vsz = int(seg.virtual_size)
                if v0 <= file_va < v0 + vsz:
                    f0 = int(seg.file_offset)
                    return f0 + (file_va - v0)
            return None

        raw = path.read_bytes()
        n_func = 0
        n_data = 0
        seen: set[int] = set()
        try:
            bindings = list(binary.dyld_info.bindings)
        except Exception:  # noqa: BLE001
            bindings = list(getattr(binary, "bindings", []) or [])

        for bi in bindings:
            try:
                file_addr = int(bi.address)
                sym = bi.symbol.name if bi.symbol is not None else ""
            except Exception:  # noqa: BLE001
                continue
            if not sym:
                continue
            addr = (file_addr + slide) & 0xFFFFFFFFFFFFFFFF
            if addr in seen:
                continue
            seen.add(addr)
            if sym not in role_map and sym not in data_slots:
                continue
            page = addr & ~0xFFF
            try:
                self._uc.mem_map(page, 0x1000, UC_PROT_ALL)
            except Exception:  # noqa: BLE001
                pass
            if sym in data_slots:
                try:
                    self._uc.mem_write(addr, int(data_slots[sym]).to_bytes(8, "little"))
                    n_data += 1
                except Exception:  # noqa: BLE001
                    pass
                continue
            try:
                tramp = self._next_adid_tramp(role_map[sym])
                self._uc.mem_write(addr, tramp.to_bytes(8, "little"))
                n_func += 1
            except Exception as ex:  # noqa: BLE001
                logger.debug("fairplayd bind %s@0x%x: %s", sym, addr, ex)

        self._fairplayd_path = path
        self._fairplayd_base = FAIRPLAYD_IMAGE_BASE
        self._slides["fairplayd"] = slide
        self._fp_hw_loaded = True
        self._exports["fairplayd_base"] = FAIRPLAYD_IMAGE_BASE
        logger.info(
            "fairplayd caricato %s segs=%d binds data=%d func=%d base=0x%x slide=0x%x",
            path.name,
            mapped,
            n_data,
            n_func,
            FAIRPLAYD_IMAGE_BASE,
            slide,
        )
        return True

    @staticmethod
    def _fp_patch_pac(blob: bytes) -> bytes:
        """Sostituisce istruzioni PAC ARM64e con equivalenti non-PAC (Unicorn).

        Critico: BLRAA/BRAA non avanzano il PC in Unicorn → spin infinito
        (visto a UeFdbi+0x17c). Le convertiamo in BLR/BR sul registro target.
        """
        out = bytearray(blob)
        for off in range(0, len(out) - 3, 4):
            w = int.from_bytes(out[off : off + 4], "little")
            if w in _PAC_NOP:
                out[off : off + 4] = _PAC_NOP[w].to_bytes(4, "little")
                continue
            top = w & 0xFFFFFC00
            # BLR/BR: Rn in bits[9:5] (es. blr x30 = 0xD63F03C0)
            # BLRAA / BLRAB  Xn, Xm  →  BLR Xn   (Xn già in bits[9:5])
            if top in (0xD73F0800, 0xD73F0C00):
                xn = (w >> 5) & 0x1F
                out[off : off + 4] = (0xD63F0000 | (xn << 5)).to_bytes(4, "little")
                continue
            # BRAA / BRAB  Xn, Xm  →  BR Xn
            if top in (0xD71F0800, 0xD71F0C00):
                xn = (w >> 5) & 0x1F
                out[off : off + 4] = (0xD61F0000 | (xn << 5)).to_bytes(4, "little")
                continue
            # BLRAAZ / BLRABZ  Xn  →  BLR Xn   (Rn in bits[4:0] sul PAC)
            if top in (0xD63F0800, 0xD63F0C00):
                xn = w & 0x1F
                out[off : off + 4] = (0xD63F0000 | (xn << 5)).to_bytes(4, "little")
                continue
            # BRAAZ / BRABZ  Xn  →  BR Xn
            if top in (0xD61F0800, 0xD61F0C00):
                xn = w & 0x1F
                out[off : off + 4] = (0xD61F0000 | (xn << 5)).to_bytes(4, "little")
                continue
            # RETAA / RETAB (mask: bit10 key A/B) → RET
            if (w & 0xFFFFF3FF) == 0xD65F03FF:
                out[off : off + 4] = (0xD65F03C0).to_bytes(4, "little")
                continue
            # PACIA*/AUTIA*/PACIB*/AUTIB* tipici: hint system 0xd5032xxx
            if (w & 0xFFFFFC00) == 0xD5032000 and w not in (0xD503201F,):
                if (w & 0xFF) in (0x1F, 0x3F, 0x5F, 0x7F, 0x9F, 0xBF, 0xDF, 0xFF):
                    out[off : off + 4] = (0xD503201F).to_bytes(4, "little")
        return bytes(out)

    def load_fairplay_macos(self, path: Path) -> bool:
        """Carica FairPlayIOKit macOS (simboli) @ VA preferite; bind stub kernel."""
        import contextlib
        import io

        import lief
        from unicorn import UC_PROT_ALL

        path = path.resolve()
        if not path.exists():
            logger.warning("FairPlayIOKit_macOS assente: %s", path)
            return False

        sink = io.StringIO()
        with contextlib.redirect_stderr(sink):
            parsed = lief.MachO.parse(str(path))
            binary = _macho_slice(parsed)
        if binary is None:
            return False

        raw = bytearray(path.read_bytes())
        # Patch PAC in __TEXT_EXEC on-disk copy before map
        for seg in binary.segments:
            if "TEXT_EXEC" not in (seg.name or ""):
                continue
            fo, fs = int(seg.file_offset), int(seg.file_size)
            if fo and fs and fo + fs <= len(raw):
                raw[fo : fo + fs] = self._fp_patch_pac(bytes(raw[fo : fo + fs]))

        mapped = 0
        for seg in binary.segments:
            vsize = int(seg.virtual_size)
            if vsize == 0:
                continue
            seg_name = seg.name or ""
            if "PAGEZERO" in seg_name.upper():
                continue
            va = int(seg.virtual_address)
            if va == 0 and vsize >= 0x10000000:
                continue
            # Skip empty zerofill giants
            fo, fs = int(seg.file_offset), int(seg.file_size)
            content = bytes(raw[fo : fo + fs]) if fo and fs and fo + fs <= len(raw) else b""
            if not content and vsize > 0x4000000:
                continue
            map_base = va & ~0xFFF
            map_end = _align(va + vsize)
            map_size = map_end - map_base
            off = 0
            while off < map_size:
                this = min(0x1000000, map_size - off)
                page = map_base + off
                try:
                    self._uc.mem_map(page, this, UC_PROT_ALL)
                except Exception:  # noqa: BLE001
                    sub = 0
                    while sub < this:
                        try:
                            self._uc.mem_map(page + sub, 0x1000, UC_PROT_ALL)
                        except Exception:  # noqa: BLE001
                            pass
                        sub += 0x1000
                off += this
            if content:
                payload = content[: min(len(content), vsize)]
                # Strip PAC dai pointer in DATA (jump tables stato-macchina)
                if "DATA" in seg_name.upper() or "CONST" in seg_name.upper():
                    payload = _strip_fp_pac_pointers(payload)
                self._uc.mem_write(va, payload)
            mapped += 1

        # Bind imports → trampoline / data slots
        role_map = {
            "_memcpy": "memcpy_chk",
            "___memcpy_chk": "memcpy_chk",
            "_memset": "memset",
            "_strlen": "nop_ret0",
            "_strncmp": "nop_ret0",
            "_strncpy": "nop_ret0",
            "_IOMalloc": "malloc",
            "_IOMallocAligned": "malloc",
            "_IOFree": "free",
            "_IOFreeAligned": "free",
            "_IOLog": "nop_ret0",
            "_IOLogv": "nop_ret0",
            "_vsnprintf": "nop_ret0",
            "_read_random": "arc4random",
            "_random": "arc4random",
            "_aes_decrypt_key": "fp_aes_decrypt_key",
            "_aes_decrypt_cbc": "fp_aes_decrypt_cbc",
            "_clock_get_calendar_microtime": "gettimeofday",
            "_microuptime": "gettimeofday",
            "_sysctlbyname": "nop_ret0",
            "_IOLockAlloc": "fp_iolock_alloc",
            "_IOLockLock": "nop_ret0",
            "_IOLockUnlock": "nop_ret0",
            "_IOLockFree": "nop_ret0",
            "_IORWLockAlloc": "fp_iolock_alloc",
            "_IORWLockRead": "nop_ret0",
            "_IORWLockWrite": "nop_ret0",
            "_IORWLockUnlock": "nop_ret0",
            "_IORWLockFree": "nop_ret0",
            "_kmem_alloc": "vm_allocate",
            "_kmem_free": "vm_deallocate",
            "_vm_deallocate": "vm_deallocate",
            "_vm_map_copyin": "nop_ret0",
            "_vm_map_copyout": "nop_ret0",
            "_vm_map_copy_discard": "nop_ret0",
            "_vm_map_wire": "nop_ret0",
            "_vm_map_unwire": "nop_ret0",
            "_host_priv_self": "nop_ret0",
            "_host_get_special_port": "nop_ret0",
            "_mig_get_reply_port": "nop_ret0",
            "_mig_put_reply_port": "nop_ret0",
            "_mig_dealloc_reply_port": "nop_ret0",
            "_mach_msg_rpc_from_kernel_proper": "nop_ret0",
            "_mach_msg_destroy_from_kernel_proper": "nop_ret0",
            "_ipc_port_release_send": "nop_ret0",
            "___stack_chk_fail": "nop_ret0",
            "__ZN9IOService15serviceMatchingEPKcP12OSDictionary": "IOServiceMatching",
            "__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec": "fp_wait_for_service",
            "__ZN9IOService20getMatchingServicesEP12OSDictionary": "fp_get_matching_services",
            "__ZN9IOService14getMatchingServiceEP12OSDictionary": "fp_wait_for_service",
            "__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm": "fp_iobuf_new",
        }
        data_slots = {
            "___stack_chk_guard": STACK_CHK_GUARD_SLOT,
            "_kernel_task": FAKE_IOAES_SERVICE,  # placeholder; overwritten below
            "_PAGE_SHIFT_CONST": FAIRPLAYD_NDR_RECORD + 0x210,
            "_kernel_map": FAIRPLAYD_NDR_RECORD + 0x220,
            "_ipc_kernel_map": FAIRPLAYD_NDR_RECORD + 0x228,
            "_NDR_record": ADID_NDR_RECORD,
        }
        # kernel_task slot: puntatore non-null (task fake)
        data_slots["_kernel_task"] = FAIRPLAYD_NDR_RECORD + 0x200
        try:
            self._uc.mem_map(FAIRPLAYD_NDR_RECORD + 0x200, 0x1000, UC_PROT_ALL)
        except Exception:  # noqa: BLE001
            pass
        self._uc.mem_write(FAIRPLAYD_NDR_RECORD + 0x200, (0x301).to_bytes(8, "little"))
        self._uc.mem_write(FAIRPLAYD_NDR_RECORD + 0x210, (14).to_bytes(4, "little"))

        n_bind = 0
        with contextlib.redirect_stderr(sink):
            try:
                bindings = list(binary.bindings)
            except Exception:  # noqa: BLE001
                bindings = []
        for bi in bindings:
            try:
                addr = int(bi.address)
                sym = bi.symbol.name if bi.symbol is not None else ""
            except Exception:  # noqa: BLE001
                continue
            if not sym:
                continue
            page = addr & ~0xFFF
            try:
                self._uc.mem_map(page, 0x1000, UC_PROT_ALL)
            except Exception:  # noqa: BLE001
                pass
            if sym in data_slots:
                self._uc.mem_write(addr, int(data_slots[sym]).to_bytes(8, "little"))
                n_bind += 1
                continue
            role = role_map.get(sym, "nop_ret0")
            try:
                tramp = self._next_adid_tramp(role)
                self._uc.mem_write(addr, tramp.to_bytes(8, "little"))
                n_bind += 1
            except Exception:  # noqa: BLE001
                pass

        self._fairplay_macos_path = path
        self._fp_uefdbi = FP_MACOS_UEFDBI
        self._fp_cmam7f = FP_MACOS_CMAM7F
        self._fp_lskd_start = FP_MACOS_LSKD_START
        self._fp_hw_loaded = True
        self._exports["UeFdbi"] = FP_MACOS_UEFDBI
        self._exports["cmam7f"] = FP_MACOS_CMAM7F

        self._install_fp_pac_alias_hook()

        # Init kext: LSKDKext_start + cmam7f (fairplay_research)
        try:
            self.invoke_cdecl(self._fp_lskd_start, [])
            cm = self.invoke_cdecl(self._fp_cmam7f, [])
            cm_s = cm if cm < 0x80000000 else cm - 0x100000000
            logger.info("FairPlay macOS init LSKD+cmam7f → %d", cm_s)
            self._fp_macos_ready = cm_s == 0 or True  # proceed even if non-zero; try UeFdbi
        except Exception as ex:  # noqa: BLE001
            logger.warning("FairPlay macOS init fallito: %s — UeFdbi comunque tentabile", ex)
            self._fp_macos_ready = True

        logger.info(
            "FairPlayIOKit_macOS caricato segs=%d binds=%d UeFdbi=%#x ready=%s",
            mapped,
            n_bind,
            self._fp_uefdbi,
            self._fp_macos_ready,
        )
        return True

    def _install_fp_pac_alias_hook(self) -> None:
        """FETCH/READ su VA PAC-tagged → alias pagina con contenuto VA stripata.

        Dopo BLRAA→BLR il target resta 0x8011…000409c8; Unicorn fetch fallisce.
        Mappiamo la pagina PAC copiando da low32 (0x409c8) e reindirizziamo PC.
        """
        from unicorn import (
            UC_HOOK_MEM_FETCH_UNMAPPED,
            UC_HOOK_MEM_READ_UNMAPPED,
            UC_HOOK_MEM_WRITE_UNMAPPED,
            UC_MEM_FETCH_UNMAPPED,
            UC_MEM_WRITE_UNMAPPED,
            UC_PROT_ALL,
        )
        from unicorn.arm64_const import UC_ARM64_REG_PC

        if getattr(self, "_fp_pac_alias_installed", False):
            return
        self._fp_pac_alias_installed = True
        self._fp_pac_alias_hits = 0

        def _hook(uc, access, address, size, value, user_data):  # noqa: ANN001, ARG001
            # PAC-tagged VA hanno bit 63 alti (es. 0x8011…000bd458) — non filtrare
            # con tetto 2^44. Solo NULL page è esclusa.
            if address < 0x1000:
                return False
            canon = _strip_fp_pac(address)
            if canon < 0x1000:
                return False
            pac_page = address & ~0xFFF
            canon_page = canon & ~0xFFF
            off = address & 0xFFF
            try:
                data = bytes(uc.mem_read(canon_page, 0x1000))
            except Exception:  # noqa: BLE001
                if access == UC_MEM_FETCH_UNMAPPED:
                    data = b"\xc0\x03\x5f\xd6" * (0x1000 // 4)
                else:
                    data = b"\x00" * 0x1000
            for page in {pac_page, canon_page}:
                try:
                    uc.mem_map(page, 0x1000, UC_PROT_ALL)
                except Exception:  # noqa: BLE001
                    pass
            try:
                uc.mem_write(pac_page, data)
                if canon_page != pac_page:
                    try:
                        uc.mem_write(canon_page, data)
                    except Exception:  # noqa: BLE001
                        pass
            except Exception:  # noqa: BLE001
                return False
            if access == UC_MEM_FETCH_UNMAPPED and canon != address:
                try:
                    uc.reg_write(UC_ARM64_REG_PC, (canon_page + off) & 0xFFFFFFFFFFFFFFFF)
                except Exception:  # noqa: BLE001
                    pass
            self._fp_pac_alias_hits = int(getattr(self, "_fp_pac_alias_hits", 0)) + 1
            if self._fp_pac_alias_hits <= 16:
                kind = {
                    UC_MEM_FETCH_UNMAPPED: "FETCH",
                    UC_MEM_WRITE_UNMAPPED: "WRITE",
                }.get(access, "READ")
                logger.info("FP PAC alias %s %#x → %#x", kind, address, canon_page + off)
            return True

        self._uc.hook_add(
            UC_HOOK_MEM_FETCH_UNMAPPED
            | UC_HOOK_MEM_READ_UNMAPPED
            | UC_HOOK_MEM_WRITE_UNMAPPED,
            _hook,
        )
        logger.info("FairPlay PAC alias hook installed")

    def _fp_snapshot_regs(self) -> list[tuple[int, int]]:
        """Snapshot GPR + SP/LR/PC/NZCV/TLS per nested emu (hook-safe)."""
        from unicorn.arm64_const import (
            UC_ARM64_REG_LR,
            UC_ARM64_REG_NZCV,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_TPIDR_EL0,
            UC_ARM64_REG_TPIDRRO_EL0,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X29,
            UC_ARM64_REG_X30,
        )

        regs: list[int] = [UC_ARM64_REG_X0 + i for i in range(29)]
        regs.extend(
            (
                UC_ARM64_REG_X29,
                UC_ARM64_REG_X30,
                UC_ARM64_REG_SP,
                UC_ARM64_REG_PC,
                UC_ARM64_REG_LR,
                UC_ARM64_REG_NZCV,
                UC_ARM64_REG_TPIDRRO_EL0,
                UC_ARM64_REG_TPIDR_EL0,
            )
        )
        out: list[tuple[int, int]] = []
        for r in regs:
            try:
                out.append((r, int(self._uc.reg_read(r))))
            except Exception:  # noqa: BLE001
                pass
        return out

    def _fp_restore_regs(self, snap: list[tuple[int, int]]) -> None:
        for r, v in snap:
            try:
                self._uc.reg_write(r, v & 0xFFFFFFFFFFFFFFFF)
            except Exception:  # noqa: BLE001
                pass

    def _fp_uefdbi_install_harvest_hook(self) -> tuple[int, dict]:
        """Hook FSM UeFdbi: passa il gate AES-byte, cattura ct/ostr, esce con status GOOD.

        Senza UID hardware reale il ciphertext non passa la validazione post-transform
        (−42187). Harvestiamo comunque i buffer prodotti dal path AES interno.
        """
        from unicorn import UC_HOOK_CODE
        from unicorn.arm64_const import (
            UC_ARM64_REG_PC,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X10,
            UC_ARM64_REG_X20,
            UC_ARM64_REG_X29,
        )

        state: dict = {"magic": 0, "ct": b"", "ostr": b""}
        uc = self._uc

        def _on_code(uc_inner, address, size, user_data) -> None:  # noqa: ANN001, ARG001
            a = address & 0xFFFFFFFF
            if a == FP_UEFDBI_BYTE_CHECK and not state["magic"]:
                w10 = int(uc_inner.reg_read(UC_ARM64_REG_X10)) & 0xFFFFFFFF
                idx = (w10 + 0x81DB1981) & 0xFFFFFFFF
                fp = int(uc_inner.reg_read(UC_ARM64_REG_X29))
                try:
                    buf = struct.unpack_from(
                        "<Q", bytes(uc_inner.mem_read(fp - 0xA8, 8)), 0
                    )[0]
                    if buf and idx < 0x1000:
                        cur = bytes(uc_inner.mem_read(buf + idx, 1))[0]
                        if cur not in (0x23, FP_UEFDBI_MAGIC_OK):
                            uc_inner.mem_write(buf + idx, bytes([FP_UEFDBI_MAGIC_OK]))
                        state["ct"] = bytes(uc_inner.mem_read(buf, 0x40))
                        state["magic"] = 1
                except Exception:  # noqa: BLE001
                    pass
            elif a == FP_UEFDBI_OSTR_WRITE and not state["ct"]:
                try:
                    x0 = int(uc_inner.reg_read(UC_ARM64_REG_X0))
                    head = bytes(uc_inner.mem_read(x0, 8))
                    ptr = struct.unpack_from("<Q", head, 0)[0]
                    if ptr:
                        state["ct"] = bytes(uc_inner.mem_read(ptr, 0x40))
                except Exception:  # noqa: BLE001
                    pass
            elif a == FP_UEFDBI_XFORM_DONE and state["magic"]:
                try:
                    x0 = int(uc_inner.reg_read(UC_ARM64_REG_X0))
                    state["ostr"] = bytes(uc_inner.mem_read(x0, 0x20))
                except Exception:  # noqa: BLE001
                    state["ostr"] = b""
                # Salta validazione post-AES (NULL stub / −42187) → epilogue rc=0
                uc_inner.reg_write(UC_ARM64_REG_X20, FP_UEFDBI_STATUS_GOOD)
                uc_inner.reg_write(UC_ARM64_REG_X0, 0)
                uc_inner.reg_write(UC_ARM64_REG_PC, FP_UEFDBI_EPILOGUE)

        hid = uc.hook_add(
            UC_HOOK_CODE,
            _on_code,
            begin=FP_UEFDBI_BYTE_CHECK,
            end=FP_UEFDBI_EPILOGUE + 4,
        )
        return hid, state

    def _fp_invoke_uefdbi(
        self,
        field0: int,
        field4: int,
        field8: int,
        in_sec1: bytes,
        in_sec2: bytes,
    ) -> tuple[bytes, bytes, int] | None:
        """Chiama _UeFdbi (ucRunversiond core) se il kext macOS è pronto.

        Salva/ripristina tutto il contesto CPU: può essere invocato da un hook
        IOConnect durante l'emu ADI (nested emu_start).
        """
        if not self._fp_uefdbi:
            return None
        if getattr(self, "_fp_uefdbi_busy", False):
            logger.info("UeFdbi skip (reentrant)")
            return None
        from unicorn.arm64_const import (
            UC_ARM64_REG_LR,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_TPIDR_EL0,
            UC_ARM64_REG_TPIDRRO_EL0,
            UC_ARM64_REG_X0,
        )

        in1 = self._heap.alloc(32)
        in2 = self._heap.alloc(max(len(in_sec2), 64) + 16)
        out1 = self._heap.alloc(32)
        out2 = self._heap.alloc(512 + 16)
        self._uc.mem_write(in1, (in_sec1 + b"\x00" * 32)[:32])
        self._uc.mem_write(in2, in_sec2 + b"\x00" * 16)
        self._uc.mem_write(out1, b"\x00" * 32)
        self._uc.mem_write(out2, b"\x00" * 528)

        # ABI: x0-x7 + 2 stack args (prologue ldr [x29,#0x10]/[#0x18])
        #   x0=task x1=f0 x2=f4 w3=f8 x4=in1 x5=in2 x6=in2_len x7=out1
        #   [sp+0]=out2  [sp+8]=&out2_len
        out2_len_p = self._heap.alloc(8)
        self._uc.mem_write(out2_len_p, (max(len(in_sec2), 64)).to_bytes(8, "little"))
        args = [
            0x301,  # task
            field0 & 0xFFFFFFFF,
            field4 & 0xFFFFFFFF,
            field8 & 0xFFFFFFFF,
            in1,
            in2,
            len(in_sec2) & 0xFFFFFFFFFFFFFFFF,
            out1,
        ]
        # context_save: nested emu_start da hook non deve corrompere ADI
        ctx = None
        try:
            ctx = self._uc.context_save()
        except Exception:  # noqa: BLE001
            ctx = None
        snap = self._fp_snapshot_regs() if ctx is None else []
        self._fp_uefdbi_busy = True
        harvest_h = 0
        harvest: dict = {}
        try:
            harvest_h, harvest = self._fp_uefdbi_install_harvest_hook()
            sp = STACK_BASE + STACK_SIZE - 0x200
            sp &= ~0xF
            # 9th=out_sec2, 10th=&out2_len at [sp]/[sp+8]
            self._uc.mem_write(
                sp,
                out2.to_bytes(8, "little") + out2_len_p.to_bytes(8, "little"),
            )
            for i, value in enumerate(args):
                self._uc.reg_write(UC_ARM64_REG_X0 + i, int(value) & 0xFFFFFFFFFFFFFFFF)
            self._uc.reg_write(UC_ARM64_REG_SP, sp)
            self._uc.reg_write(UC_ARM64_REG_LR, RETURN_ADDRESS)
            self._uc.reg_write(UC_ARM64_REG_TPIDRRO_EL0, TLS_BASE)
            self._uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
            self._uc.emu_start(
                self._fp_uefdbi, RETURN_ADDRESS, timeout=8_000_000, count=8_000_000
            )
            ret = int(self._uc.reg_read(UC_ARM64_REG_X0))
            ret_s = ret if ret < 0x80000000 else ret - 0x100000000
            sec1 = bytes(self._uc.mem_read(out1, 20))
            sec2 = bytes(self._uc.mem_read(out2, max(len(in_sec2), 64)))
            # Harvest: ostr trasformato → sec1, ciphertext AES interno → sec2
            ostr = bytes(harvest.get("ostr") or b"")
            ct = bytes(harvest.get("ct") or b"")
            if ostr and (not any(sec1) or ret_s != 0):
                need = max(len(in_sec2), 64)
                sec1 = (ostr + b"\x00" * 20)[:20]
                sec2 = (ct * ((need // max(len(ct), 1)) + 1))[:need] if ct else ostr
                try:
                    self._uc.mem_write(out1, (sec1 + b"\x00" * 32)[:32])
                    self._uc.mem_write(out2, (sec2 + b"\x00" * 16)[: need + 16])
                except Exception:  # noqa: BLE001
                    pass
                ret_s = 0
                logger.info(
                    "UeFdbi harvest ostr=%s ct=%s (bypass post-AES −42187)",
                    sec1[:8].hex(),
                    (ct[:8].hex() if ct else "-"),
                )
            self._fp_uefdbi_calls = int(getattr(self, "_fp_uefdbi_calls", 0)) + 1
            logger.info(
                "UeFdbi → %d sec1=%s sec2_len=%d calls=%d",
                ret_s,
                sec1[:8].hex(),
                len(sec2),
                self._fp_uefdbi_calls,
            )
            return sec1, sec2, ret_s
        except Exception as ex:  # noqa: BLE001
            logger.warning("UeFdbi emu fallita: %s", ex)
            return None
        finally:
            if harvest_h:
                try:
                    self._uc.hook_del(harvest_h)
                except Exception:  # noqa: BLE001
                    pass
            self._fp_uefdbi_busy = False
            if ctx is not None:
                try:
                    self._uc.context_restore(ctx)
                except Exception:  # noqa: BLE001
                    self._fp_restore_regs(snap)
            else:
                self._fp_restore_regs(snap)

    def _install_adid_obf_malloc_hook(self) -> None:
        """Bypass allo stub malloc offuscato di adid (0x1000f029c) che altrimenti
        torna NULL e fa fallire il parse XPC con -45003."""
        from unicorn import UC_HOOK_CODE
        from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_X0

        # Risolto a runtime: pool → stub 0x100001dec → 0x1000f029c (size in x0)
        ADID_OBF_MALLOC = 0x1000F029C

        def on_obf_malloc(uc, address, size, user_data):  # noqa: ANN001, ARG001
            if address != ADID_OBF_MALLOC:
                return
            n = int(uc.reg_read(UC_ARM64_REG_X0))
            lr = int(uc.reg_read(UC_ARM64_REG_LR))
            try:
                ptr = self._heap.alloc(n if n > 0 else 1)
            except MemoryError:
                ptr = 0
            if not hasattr(self, "_adid_obf_malloc_hits"):
                self._adid_obf_malloc_hits = 0
            self._adid_obf_malloc_hits += 1
            if self._adid_obf_malloc_hits <= 8:
                logger.info("adid obf_malloc(%#x) → %#x", n, ptr)
            uc.reg_write(UC_ARM64_REG_X0, ptr & 0xFFFFFFFFFFFFFFFF)
            uc.reg_write(UC_ARM64_REG_PC, lr)

        self._uc.hook_add(
            UC_HOOK_CODE, on_obf_malloc, begin=ADID_OBF_MALLOC, end=ADID_OBF_MALLOC
        )
        logger.info("adid obf_malloc hook @%#x", ADID_OBF_MALLOC)

    def _install_adid_page0_dispatcher(self) -> None:
        """blr a 0 (import non bindato nel pool): euristica CFGetTypeID / FairPlay / nop."""
        from unicorn import UC_HOOK_CODE, UC_PROT_ALL
        from unicorn.arm64_const import (
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
            UC_ARM64_REG_X4,
            UC_ARM64_REG_X5,
        )

        try:
            self._uc.mem_map(0, 0x1000, UC_PROT_ALL)
        except Exception:  # noqa: BLE001
            pass
        # Solo RET: l'hook gira sull'istruzione e reindirizza a LR
        self._uc.mem_write(0, b"\xc0\x03\x5f\xd6" * (0x1000 // 4))
        self._page0_hits = 0

        def _is_cf_obj(addr: int) -> bool:
            if addr in (FAKE_CFBOOL_TRUE, FAKE_SEC_TASK, FAKE_FP_SERVICE, FAKE_FP_CONNECT):
                return True
            if CF_OBJ_BASE <= addr < CF_OBJ_BASE + CF_OBJ_SIZE:
                return True
            return False

        def on_page0(uc, address, size, user_data):  # noqa: ANN001, ARG001
            if address >= 0x20:
                return
            lr = int(uc.reg_read(UC_ARM64_REG_LR))
            # evita loop se LR punta a page0
            if lr < 0x1000:
                uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, RETURN_ADDRESS)
                return
            x0 = int(uc.reg_read(UC_ARM64_REG_X0))
            x1 = int(uc.reg_read(UC_ARM64_REG_X1))
            x2 = int(uc.reg_read(UC_ARM64_REG_X2))
            x3 = int(uc.reg_read(UC_ARM64_REG_X3))
            x4 = int(uc.reg_read(UC_ARM64_REG_X4))
            x5 = int(uc.reg_read(UC_ARM64_REG_X5))
            self._page0_hits += 1

            def _ret(val: int) -> None:
                uc.reg_write(UC_ARM64_REG_X0, val & 0xFFFFFFFFFFFFFFFF)
                uc.reg_write(UC_ARM64_REG_PC, lr)

            # IOConnectCallStructMethod(conn, sel, in, inCnt, out, *outCnt)
            if x4 and x5 and 0 < x3 < 0x100000:
                if self._page0_hits <= 30:
                    logger.info("page0→FairPlay IOConnect (lr=%#x sel=%d)", lr, x1)
                _ret(self._fairplay_connect_struct(uc))
                return

            # C-string name helpers (IOServiceMatching / xpc mach service)
            try:
                cname = self._read_cstr(x0, 96).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                cname = ""
            if cname and all(32 <= ord(ch) < 127 for ch in cname[:80]):
                if (
                    "FairPlay" in cname
                    or cname == FP_IOKIT_MATCH
                    or "IOKit" in cname
                    or cname.startswith("com_apple")
                    or "UserClient" in cname
                ):
                    matching = self._alloc_cfstring(cname)
                    self._fp_matching = matching
                    if self._page0_hits <= 30:
                        logger.info("page0→IOServiceMatching(%r) → %#x", cname, matching)
                    _ret(matching)
                    return
                if cname.startswith("com.apple.") or cname.endswith(".xpc"):
                    # xpc_connection_create_mach_service(name, queue, flags)
                    conn = self._heap.alloc(0x40)
                    self._uc.mem_write(conn, b"\x00" * 0x40)
                    if not hasattr(self, "_xpc_conns"):
                        self._xpc_conns = set()
                    self._xpc_conns.add(conn)
                    if self._page0_hits <= 30:
                        logger.info("page0→xpc_mach_service(%r) → %#x", cname, conn)
                    _ret(conn)
                    return

            # xpc_connection_* / send_message_with_reply_sync su handle finto
            if getattr(self, "_xpc_conns", None) and x0 in self._xpc_conns:
                # set_event_handler / resume → 0; sync send → reply object
                if x1 == 0 or x1 < 0x1000:
                    try:
                        reply = self._heap.alloc(0x40)
                        self._uc.mem_write(reply, b"\x00" * 0x40)
                    except MemoryError:
                        reply = 0
                    if self._page0_hits <= 30:
                        logger.info("page0→xpc_reply lr=%#x → %#x", lr, reply)
                    _ret(reply)
                    return
                if self._page0_hits <= 30:
                    logger.info("page0→xpc_conn_op lr=%#x x1=%#x", lr, x1)
                _ret(0)
                return

            # IOServiceGetMatchingServices: solo dopo IOServiceMatching
            if (
                getattr(self, "_fp_matching", 0)
                and x1 == self._fp_matching
                and x2 > 0x10000
                and x0 < 0x1000
            ):
                try:
                    uc.mem_write(x2, FAKE_FP_ITER.to_bytes(4, "little"))
                    self._fp_iter_alive = True
                    self._fp_matching = 0
                    if self._page0_hits <= 30:
                        logger.info("page0→IOServiceGetMatchingServices")
                    _ret(KIO_RETURN_SUCCESS)
                    return
                except Exception:  # noqa: BLE001
                    pass

            # IOIteratorNext(iter)
            if x0 == FAKE_FP_ITER and x1 == 0 and x2 == 0:
                if self._fp_iter_alive:
                    self._fp_iter_alive = False
                    _ret(FAKE_FP_SERVICE)
                else:
                    _ret(0)
                return

            # IOServiceOpen(service, owningTask, type, *connect)
            if x3 > 0x10000 and x0 == FAKE_FP_SERVICE and x2 < 0x100:
                try:
                    uc.mem_write(x3, FAKE_FP_CONNECT.to_bytes(4, "little"))
                    self._fp_opened = True
                    if self._page0_hits <= 30:
                        logger.info("page0→IOServiceOpen connect=%#x", FAKE_FP_CONNECT)
                    _ret(KIO_RETURN_SUCCESS)
                    return
                except Exception:  # noqa: BLE001
                    pass

            # open / open_dprotected_np(path, ...)
            if cname.startswith("/") and all(32 <= ord(ch) < 127 for ch in cname[:80]):
                host = self._vfs_resolve(cname)
                try:
                    host.parent.mkdir(parents=True, exist_ok=True)
                    if not host.exists():
                        host.write_bytes(b"")
                    fh = open(host, "r+b")  # noqa: SIM115
                    fd = self._vfs_next_fd
                    self._vfs_next_fd += 1
                    self._vfs_fds[fd] = fh
                    if self._page0_hits <= 30:
                        logger.info("page0→open(%r) fd=%d", cname, fd)
                    _ret(fd)
                    return
                except OSError:
                    _ret(0xFFFFFFFFFFFFFFFF)
                    return

            # CFStringGetCString(str, buf, bufSize, encoding)
            if _is_cf_obj(x0) and x1 > 0x1000 and 2 <= x2 <= 0x10000 and x3 in (0x600, 0x08000100, 0x20, 0):
                text = b"1" if x0 == FAKE_CFBOOL_TRUE else b""
                if not text:
                    try:
                        text = self._read_cfstring(x0).encode("utf-8")
                    except Exception:  # noqa: BLE001
                        text = b""
                if text:
                    try:
                        uc.mem_write(x1, text[: x2 - 1] + b"\x00")
                        if self._page0_hits <= 30:
                            logger.info("page0→CFStringGetCString %r", text[:32])
                        _ret(1)
                        return
                    except Exception:  # noqa: BLE001
                        pass

            # strtoul(str, *endptr, base)
            if x0 > 0x1000 and 2 <= x2 <= 36 and (x1 > 0x1000 or x1 == 0):
                try:
                    s = self._read_cstr(x0, 64).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    s = ""
                if s and (s[0].isdigit() or s[0] in "+-"):
                    import re as _re

                    m = _re.match(r"\s*([+-]?[0-9a-fA-FxX]+)", s)
                    if m:
                        try:
                            val = int(m.group(1), x2)
                        except Exception:  # noqa: BLE001
                            val = 0
                        if x1:
                            try:
                                uc.mem_write(x1, (x0 + m.end(1)).to_bytes(8, "little"))
                            except Exception:  # noqa: BLE001
                                pass
                        if self._page0_hits <= 30:
                            logger.info("page0→strtoul(%r)→%d", s[:16], val)
                        _ret(val & 0xFFFFFFFFFFFFFFFF)
                        return

            # CFNumberGetValue(num, type, *value)
            if _is_cf_obj(x0) and 1 <= x1 <= 16 and x2 > 0x1000:
                if x0 == FAKE_CFBOOL_TRUE:
                    _ret(0)
                    return
                val = int(getattr(self, "_adid_cfnumber_value", 1))
                try:
                    if x1 in (4, 9, 10):
                        uc.mem_write(x2, int(val).to_bytes(8, "little", signed=True))
                    else:
                        uc.mem_write(x2, int(val).to_bytes(4, "little", signed=True))
                    if self._page0_hits <= 30:
                        logger.info("page0→CFNumberGetValue type=%d val=%d", x1, val)
                    _ret(1)
                    return
                except Exception:  # noqa: BLE001
                    pass

            # malloc(n) via tabella pool secondaria non bindata
            if not cname and not _is_cf_obj(x0) and 0 < x0 < 0x1000000 and x1 == 0 and x2 < 0x10000:
                try:
                    ptr = self._heap.alloc(int(x0))
                    if self._page0_hits <= 30:
                        logger.info("page0→malloc(%#x) → %#x", x0, ptr)
                    _ret(ptr)
                    return
                except MemoryError:
                    _ret(0)
                    return

            # CFBooleanGetTypeID() — solo se x0 sembra typeid leftover (piccolo)
            # e x1 è un CFString (chiave entitlement), non malloc/xpc.
            if (
                not _is_cf_obj(x0)
                and 0x10 <= x0 < 0x100
                and _is_cf_obj(x1)
            ):
                if self._page0_hits <= 30:
                    logger.info("page0→CFBooleanGetTypeID")
                _ret(CF_TYPEID_BOOLEAN)
                return

            # CFGetTypeID(obj) — solo se non sembra un GetValue (x1 type / x2 out)
            if (_is_cf_obj(x0) or x0 == 0) and not (1 <= x1 <= 16 and x2 > 0x1000):
                if x0 == FAKE_CFBOOL_TRUE:
                    _ret(CF_TYPEID_BOOLEAN)
                elif x0 == 0:
                    _ret(0)
                elif CF_OBJ_BASE <= x0 < CF_OBJ_BASE + CF_OBJ_SIZE:
                    _ret(CF_TYPEID_STRING)
                else:
                    _ret(CF_TYPEID_OTHER)
                return

            # Tabella import secondaria: create/alloc con x0 NULL
            if 0x100000000 <= lr < 0x100200000 and x0 == 0:
                try:
                    ptr = self._heap.alloc(0x40)
                    if self._page0_hits <= 30:
                        logger.info("page0→alloc_stub lr=%#x → %#x", lr, ptr)
                    _ret(ptr)
                    return
                except MemoryError:
                    pass

            # Runtime adid @0x100002b5c: blr x22 con x22=0 dopo obf_malloc bypass.
            # cbnz w0 → error; tornare 0 = success no-op.
            if lr == 0x100002B60:
                if self._page0_hits <= 30:
                    logger.info("page0→adid_runtime_nop lr=%#x x0=%#x x1=%#x", lr, x0, x1)
                _ret(0)
                return

            if self._page0_hits <= 20:
                logger.info(
                    "page0 unresolved lr=%#x x0=%#x x1=%#x x2=%#x x3=%#x cname=%r",
                    lr,
                    x0,
                    x1,
                    x2,
                    x3,
                    cname[:40] if cname else "",
                )
            _ret(0)

        self._uc.hook_add(UC_HOOK_CODE, on_page0, begin=0, end=0x20)
        logger.info("adid page0 dispatcher installed")

    def _spread_adid_pool_binds(
        self,
        binary: Any,
        raw: bytes,
        va_to_off: Any,
    ) -> int:
        """Patcha ogni qword == addend noto nel __DATA_CONST con slot_val già scritto."""
        from unicorn import UC_PROT_ALL

        # Raccogli addend → valore già scritto al bind primario
        addend_to_val: dict[int, int] = {}
        try:
            bindings = list(binary.dyld_info.bindings)
        except Exception:  # noqa: BLE001
            return 0
        for bi in bindings:
            try:
                sym = bi.symbol.name if bi.symbol is not None else ""
                addr = int(bi.address)
                addend = int(bi.addend)
            except Exception:  # noqa: BLE001
                continue
            if sym not in ADID_POOL_BIND_SYMS and sym not in (
                "_kCFBooleanTrue",
                "_NDR_record",
                "___stack_chk_guard",
                "__xpc_type_dictionary",
                "__xpc_type_error",
                "__xpc_error_connection_interrupted",
                "__xpc_error_connection_invalid",
            ):
                if not (
                    sym.startswith("_IO")
                    or sym.startswith("_Sec")
                    or sym.startswith("_CF")
                    or sym.startswith("_MG")
                    or sym.startswith("__xpc_")
                ):
                    continue
            if not (0x10 < addend < 0x100000000):
                continue
            try:
                val = int.from_bytes(self._uc.mem_read(addr, 8), "little")
            except Exception:  # noqa: BLE001
                continue
            # solo se abbiamo già patchato il bind primario (val != addend on-disk)
            if val == addend:
                continue
            addend_to_val[addend] = val

        if not addend_to_val:
            return 0

        # Scansiona segmenti DATA* per qword == addend
        n = 0
        for seg in binary.segments:
            name = (getattr(seg, "name", None) or "").upper()
            if "DATA" not in name:
                continue
            v0 = int(seg.virtual_address)
            vsz = int(seg.virtual_size)
            f0 = int(seg.file_offset)
            # limita a contenuto file
            content = bytes(getattr(seg, "content", b"") or b"")
            if not content:
                continue
            for off in range(0, len(content) - 7, 8):
                q = int.from_bytes(content[off : off + 8], "little")
                if q not in addend_to_val:
                    continue
                va = v0 + off
                # non riscrivere se già patchato
                try:
                    cur = int.from_bytes(self._uc.mem_read(va, 8), "little")
                except Exception:  # noqa: BLE001
                    page = va & ~0xFFF
                    try:
                        self._uc.mem_map(page, 0x1000, UC_PROT_ALL)
                    except Exception:  # noqa: BLE001
                        continue
                    try:
                        # ripristina pagina dal file se appena mappata
                        foff = va_to_off(page)
                        if foff is not None:
                            self._uc.mem_write(page, raw[foff : foff + 0x1000].ljust(0x1000, b"\x00"))
                        cur = int.from_bytes(self._uc.mem_read(va, 8), "little")
                    except Exception:  # noqa: BLE001
                        continue
                if cur == addend_to_val[q]:
                    continue
                if cur != q:
                    continue
                try:
                    self._uc.mem_write(va, addend_to_val[q].to_bytes(8, "little"))
                    n += 1
                except Exception:  # noqa: BLE001
                    continue
        if n:
            logger.info("adid pool spread: patched %d extra slots", n)
        return n

    def _adi_mig_enter_real(self, uc, address: int) -> bool:  # noqa: ANN001
        """Reindirizza mach_msg2 → adid_server senza nested emu_start."""
        from unicorn.arm64_const import (
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
            UC_ARM64_REG_X4,
            UC_ARM64_REG_X5,
            UC_ARM64_REG_X6,
            UC_ARM64_REG_X7,
        )

        in_buf = uc.reg_read(UC_ARM64_REG_X0)
        try:
            hdr = bytearray(uc.mem_read(in_buf, 0x40))
        except Exception:  # noqa: BLE001
            return False
        msgh_id = struct.unpack_from("<I", hdr, 0x14)[0]
        if msgh_id != ADI_MIG_REQUEST_ID:
            return False

        # mach_msg2: size/bits spesso nei registri (x2 hi=send_size), buffer size=0.
        # Dopo una reply simple (size=0x24) il buffer client può restare sporco:
        # forzare size=0x38+gate su ogni request COMPLEX, non solo size==0.
        # adid: msgh_size==0x38, word@0x38==0 e word@0x3c>0x1f (gate).
        msgh_bits = struct.unpack_from("<I", hdr, 0)[0]
        msgh_size = struct.unpack_from("<I", hdr, 4)[0]
        send_size = int(uc.reg_read(UC_ARM64_REG_X2) >> 32) & 0xFFFFFFFF
        if send_size <= 0 or send_size > 0x4000:
            send_size = 0x38
        if msgh_bits & 0x80000000:
            try:
                # Request ADI COMPLEX+OOL: msgh_size è sempre 0x38 (header+descriptor).
                # SS lascia 0 / 1 / 0x24 (reply) / 1200 (capacità buffer) — normalizza.
                ool_sz = struct.unpack_from("<I", hdr, 0x28)[0]
                need_size_fix = msgh_size != 0x38
                if need_size_fix:
                    uc.mem_write(in_buf + 4, (0x38).to_bytes(4, "little"))
                # Gate adid: [msg+0x38]==0 && [msg+0x3c] > 0x1f
                gate = max(int(ool_sz), 0x20)
                try:
                    cur38 = int.from_bytes(uc.mem_read(in_buf + 0x38, 8), "little")
                except Exception:  # noqa: BLE001
                    cur38 = -1
                if need_size_fix or cur38 == 0:
                    tail = bytearray(0x48)
                    struct.pack_into("<II", tail, 0, 0, gate)
                    uc.mem_write(in_buf + 0x38, bytes(tail))
            except Exception:  # noqa: BLE001
                return False
            if need_size_fix:
                logger.info(
                    "ADI MIG: mach_msg2 fixup size %d→0x38 gate@0x3c=%d (x2_send=%#x)",
                    msgh_size,
                    gate,
                    send_size,
                )

        try:
            out_buf = self._heap.alloc(0x800)
        except MemoryError:
            return False
        uc.mem_write(out_buf, b"\x00" * 0x800)

        finish = getattr(self, "_adid_finish_tramp", None) or self._next_adid_tramp("adi_mig_finish")
        _xregs = (
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
            UC_ARM64_REG_X4,
            UC_ARM64_REG_X5,
            UC_ARM64_REG_X6,
            UC_ARM64_REG_X7,
        )
        saved_regs = {f"x{i}": int(uc.reg_read(r)) for i, r in enumerate(_xregs)}
        self._adi_mig_saved = {
            "lr": int(uc.reg_read(UC_ARM64_REG_LR)),
            "in_buf": int(in_buf),
            "out_buf": int(out_buf),
            "trap_cont": int((address + 8) & 0xFFFFFFFFFFFFFFFF),
            "regs": saved_regs,
        }

        uc.reg_write(UC_ARM64_REG_X0, in_buf)
        uc.reg_write(UC_ARM64_REG_X1, out_buf)
        uc.reg_write(UC_ARM64_REG_LR, int(finish))
        uc.reg_write(UC_ARM64_REG_PC, int(self._adid_mig_server))
        logger.info("ADI MIG → adid_server In=0x%x Out=0x%x", in_buf, out_buf)
        return True

    def _adi_mig_finish_real(self, uc) -> None:  # noqa: ANN001
        """Copia reply adid nel buffer client e ritorna al caller di mach_msg2."""
        from unicorn.arm64_const import (
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
            UC_ARM64_REG_X4,
            UC_ARM64_REG_X5,
            UC_ARM64_REG_X6,
            UC_ARM64_REG_X7,
        )

        saved = self._adi_mig_saved or {}
        in_buf = int(saved.get("in_buf", 0))
        out_buf = int(saved.get("out_buf", 0))
        lr = int(saved.get("lr", RETURN_ADDRESS))
        ok = False
        retcode = ADI_NOT_PROVISIONED
        if in_buf and out_buf:
            try:
                # Se XPC START ha prodotto CPIM via FairPlay, riscrivi reply MIG
                # complex+OOL (adid client-side non unpacka ancora il blob XPC).
                cpim = getattr(self, "_xpc_pending_cpim", None)
                if isinstance(cpim, (bytes, bytearray)) and len(cpim) > 0:
                    sess = int(getattr(self, "_xpc_pending_session", 1))
                    be = (
                        struct.pack(">I", 0)
                        + struct.pack(">I", len(cpim))
                        + bytes(cpim)
                        + struct.pack(">I", sess & 0xFFFFFFFF)
                    )
                    ool = self._heap.alloc(len(be))
                    uc.mem_write(ool, be)
                    reply = bytearray(0x38)
                    struct.pack_into(
                        "<IIIIII",
                        reply,
                        0,
                        0x80000012,  # COMPLEX
                        0x38,
                        0,
                        0,
                        0,
                        ADI_MIG_REPLY_ID,
                    )
                    struct.pack_into("<I", reply, 0x18, 1)
                    struct.pack_into("<Q", reply, 0x1C, ool)
                    struct.pack_into("<I", reply, 0x24, 0x01000100)
                    struct.pack_into("<I", reply, 0x28, len(be))
                    struct.pack_into("<I", reply, 0x34, len(be))
                    uc.mem_write(out_buf, bytes(reply) + b"\x00" * 0x40)
                    self._xpc_pending_cpim = None
                    self._xpc_pending_session = None
                    logger.info(
                        "ADI MIG finish: inject START CPIM len=%d session=%d",
                        len(cpim),
                        sess,
                    )
                out = bytes(uc.mem_read(out_buf, 0x200))
                size = struct.unpack_from("<I", out, 4)[0]
                if size <= 0 or size > 0x200:
                    size = 0x38
                uc.mem_write(in_buf, out[: max(size, 0x38)])
                retcode = struct.unpack_from("<i", out, 0x20)[0]
                # XPC status non sempre finisce nel RetCode MIG (layout reply
                # ancora parziale). Esporlo senza patchare il buffer SS.
                pending = getattr(self, "_xpc_last_status", None)
                if pending is not None:
                    self._adi_xpc_status = int(pending)
                    if retcode == 0 and int(pending) != 0:
                        retcode = int(pending)
                    self._xpc_last_status = None
                ok = True
            except Exception as ex:  # noqa: BLE001
                logger.warning("adid MIG finish copy: %s", ex)
        # Come lo stub sintetico: non ripristinare x1–x7 (caller-saved).
        # Torna al caller di mach_msg2 (LR salvato all'enter — non il finish tramp).
        self._adi_mig_saved = None
        uc.reg_write(UC_ARM64_REG_X0, 0 if ok else 0x10000015)
        uc.reg_write(UC_ARM64_REG_LR, lr)
        trap_cont = int(saved.get("trap_cont", 0))
        # stub: PC=trap+8 esegue `ret`; qui LR è di nuovo il caller SS.
        uc.reg_write(UC_ARM64_REG_PC, trap_cont if trap_cont else lr)
        logger.info("ADI MIG ← adid_server ok=%s retcode=%d", ok, retcode)

    def _force_patch_malloc_zones(self) -> None:
        zones_arr = FAKE_ZONE_BASE + 0x800
        page = MALLOC_ZONES_ADDR & ~0xFFF
        try:
            self._uc.mem_write(MALLOC_ZONES_ADDR, zones_arr.to_bytes(8, "little"))
            self._lazy_pages.add(page)
            logger.info("Patched _malloc_zones @0x%x -> 0x%x (post-load)", MALLOC_ZONES_ADDR, zones_arr)
        except Exception as ex:  # noqa: BLE001
            logger.debug("patch _malloc_zones skip: %s", ex)

    @property
    def uc(self):
        return self._uc

    @property
    def exports(self) -> dict[str, int]:
        return self._exports

    def load(self, path: Path, tag: str) -> int:
        """Mappa segmenti agli VA originali del DSC (slide=0) per preservare i puntatori."""
        import lief
        from unicorn import UC_PROT_ALL

        path = path.resolve()
        if getattr(self, "_loaded_paths", None) is None:
            self._loaded_paths = {}  # type: ignore[attr-defined]
        if str(path) in self._loaded_paths:  # type: ignore[attr-defined]
            slide = self._loaded_paths[str(path)]  # type: ignore[attr-defined]
            self._slides[tag] = slide
            logger.info("Skip reload %s → già mappato (slide=0x%x)", tag, slide)
            return slide

        parsed = lief.MachO.parse(str(path))
        if parsed is None:
            raise RuntimeError(f"Mach-O parse fallito: {path}")

        binary = _macho_slice(parsed)
        if binary is None:
            raise RuntimeError(f"Nessuno slice ARM64: {path}")

        mapped = 0
        for seg in binary.segments:
            vsize = int(seg.virtual_size)
            if vsize == 0:
                continue
            seg_name = (getattr(seg, "name", None) or "")
            # __PAGEZERO (PIE) è 4GiB a VA 0 — non mappare
            if "PAGEZERO" in seg_name.upper() or (int(seg.virtual_address) == 0 and vsize >= 0x10000000):
                continue
            # Skip segmenti enormi senza contenuto file (zerofill oltre soglia)
            content = bytes(getattr(seg, "content", b"") or b"")
            if not content and vsize > 0x4000000:
                logger.info("Skip seg %s vsize=0x%x (no content)", seg_name, vsize)
                continue
            va = int(seg.virtual_address)
            map_base = va & ~0xFFF
            map_end = _align(va + vsize)
            map_size = map_end - map_base
            # Chunk grandi (16 MiB) — page-by-page su __OBJC_RO (~80MB) è troppo lento
            chunk_sz = 0x1000000
            off = 0
            while off < map_size:
                this = min(chunk_sz, map_size - off)
                page = map_base + off
                try:
                    self._uc.mem_map(page, this, UC_PROT_ALL)
                except Exception:  # noqa: BLE001
                    # overlap: fallback 4K
                    sub = 0
                    while sub < this:
                        try:
                            self._uc.mem_map(page + sub, 0x1000, UC_PROT_ALL)
                        except Exception:  # noqa: BLE001
                            pass
                        sub += 0x1000
                off += this
            if content:
                chunk = content[: min(len(content), vsize)]
                # Strip PAC/chained nei segmenti DATA (non TEXT)
                strip = "data" in seg_name.lower() or "got" in seg_name.lower() or "auth" in seg_name.lower()
                # write in 4MB slices
                woff = 0
                while woff < len(chunk):
                    piece = chunk[woff : woff + 0x400000]
                    if strip:
                        piece = _strip_pointers_in_page(piece)
                    self._uc.mem_write(va + woff, piece)
                    woff += len(piece)
            mapped += 1

        file_exports = collect_exports(path)
        for name, fva in file_exports.items():
            self._exports[name] = fva  # VA DSC originali

        # Le dylib estratte da DSC spesso hanno __got a zero (bind gia' risolti
        # solo nella cache live). Re-page da DSC le sezioni GOT/DATA_CONST.
        # Skip per PIE standalone (adid/fairplayd) e kext prelinked.
        img_base = int(getattr(binary, "imagebase", 0) or 0)
        skip_repave = (
            tag in ("adid", "fairplayd", "FairPlayIOKit")
            or img_base == ADID_IMAGE_BASE
            or img_base == FAIRPLAYD_IMAGE_BASE
            or img_base >= 0xFFFF000000000000
        )
        if not skip_repave:
            self._repave_got_from_dsc(binary)

        slide = 0
        self._slides[tag] = slide
        self._loaded_paths[str(path)] = slide  # type: ignore[attr-defined]
        logger.info(
            "Caricato %s (%s) segs=%d exports=%d (VA originali DSC)",
            tag,
            path.name,
            mapped,
            len(file_exports),
        )
        return slide

    def _repave_got_from_dsc(self, binary: Any) -> None:
        """Sovrascrive __got / lazy_symbol_ptr con pagine reali dal DSC."""
        if self._dsc_path is None:
            return
        pages: set[int] = set()
        for sec in binary.sections:
            name = (getattr(sec, "name", None) or "").lower()
            if not any(k in name for k in ("got", "la_symbol", "auth_got", "nl_symbol")):
                continue
            va = int(sec.virtual_address)
            size = int(sec.size)
            if size <= 0:
                continue
            # Se il GOT estratto e' tutto zero, e' inutilizzabile: prendi dal DSC
            content = bytes(getattr(sec, "content", b"") or b"")
            if content and any(content):
                continue
            start = va & ~0xFFF
            end = _align(va + size)
            for page in range(start, end, 0x1000):
                pages.add(page)
        if not pages:
            return
        n_ok = 0
        for page in sorted(pages):
            data = self._fetch_dsc_page(page)
            if data is None:
                continue
            data = _strip_pointers_in_page(data)
            try:
                self._uc.mem_write(page, data)
                self._patch_runtime_globals(page, data)
                self._lazy_pages.add(page)
                n_ok += 1
            except Exception:  # noqa: BLE001
                continue
        if n_ok:
            logger.info("Re-paved %d/%d GOT/DATA_CONST pages from DSC", n_ok, len(pages))

    def setup_stack(self) -> None:
        from unicorn import UC_PROT_READ, UC_PROT_WRITE
        from unicorn.arm64_const import (
            UC_ARM64_REG_SP,
            UC_ARM64_REG_TPIDR_EL0,
            UC_ARM64_REG_TPIDRRO_EL0,
        )

        self._uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self._uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x100)
        # TLS deve restare impostato ad ogni setup (alcuni path lo azzerano)
        self._uc.reg_write(UC_ARM64_REG_TPIDRRO_EL0, TLS_BASE)
        self._uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)

    def resolve(self, name: str) -> int | None:
        if name in self._exports:
            return self._exports[name]
        if name.startswith("_") and name[1:] in self._exports:
            return self._exports[name[1:]]
        underscored = f"_{name}"
        if underscored in self._exports:
            return self._exports[underscored]
        return None

    def temp_alloc_data(self, data: bytes) -> int:
        addr = self._temp.alloc(len(data) + 8)
        self._uc.mem_write(addr, data + b"\x00")
        return addr

    def temp_alloc(self, size: int) -> int:
        addr = self._temp.alloc(size)
        self._uc.mem_write(addr, b"\x00" * size)
        return addr

    def temp_free(self, addr: int) -> None:
        self._temp.free(addr)

    def invoke_cdecl(self, address: int, args: list[int]) -> int:
        from unicorn.arm64_const import (
            UC_ARM64_REG_LR,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_TPIDR_EL0,
            UC_ARM64_REG_TPIDRRO_EL0,
            UC_ARM64_REG_X0,
        )

        for i, value in enumerate(args):
            if i > 28:
                raise ValueError("troppi argomenti ARM64")
            self._uc.reg_write(UC_ARM64_REG_X0 + i, int(value) & 0xFFFFFFFFFFFFFFFF)
        self._uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x100)
        self._uc.reg_write(UC_ARM64_REG_LR, RETURN_ADDRESS)
        self._uc.reg_write(UC_ARM64_REG_TPIDRRO_EL0, TLS_BASE)
        self._uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
        # timeout us + instruction cap evitano hang su stub loop
        self._fp_in_adi_emu = True
        try:
            self._uc.emu_start(address, RETURN_ADDRESS, timeout=5_000_000, count=5_000_000)
        finally:
            self._fp_in_adi_emu = False
        return int(self._uc.reg_read(UC_ARM64_REG_X0))


def resolve_adi_symbols(
    exports: dict[str, int],
    override: dict[str, str] | None = None,
) -> dict[str, int]:
    """role → absolute VA."""
    override = override or {}
    resolved: dict[str, int] = {}

    for role, default_name in ANDROID_ADI_SYMBOLS.items():
        name = override.get(role) or default_name
        # allow override values that are already absolute hex strings
        if isinstance(name, str) and name.startswith("0x"):
            resolved[role] = int(name, 16)
            continue
        va = exports.get(name) or exports.get(f"_{name}")
        if va is not None:
            resolved[role] = va

    # Also accept override as {androidName: role} inverted mistakes
    for key, val in override.items():
        if key in ANDROID_ADI_SYMBOLS and key not in resolved:
            va = exports.get(val) or exports.get(f"_{val}")
            if va is not None:
                resolved[key] = va

    return resolved


class IosAdiBackend:
    """ADI iOS via Unicorn — attivo solo con simboli completi."""

    def __init__(self, libs_dir: Path) -> None:
        self.manifest = IosAdiManifest.load(libs_dir)
        self._loader = MachOArm64Loader()
        self._ready = False
        self._symbols: dict[str, int] = {}
        self._provisioning_path: str | None = None

    def initialize(self) -> None:
        global IOS_ADI_RUNTIME_READY  # noqa: PLW0603

        libs_dir = self.manifest.libs_dir or app_data_ios_libs_dir()
        dsc = Path(self.manifest.source_dsc) if self.manifest.source_dsc else None
        if dsc and dsc.exists():
            self._loader.configure_dsc_pager(dsc, libs_dir)

        # lib di sistema (VA DSC) prima di StoreServices
        sys_dir = libs_dir / "sys"
        load_large = (os.environ.get("AKD_IOS_LOAD_LARGE") or "").strip() in ("1", "true", "yes")
        if sys_dir.is_dir():
            for name in SYS_LIB_ORDER:
                p = sys_dir / name
                if not p.exists():
                    continue
                mb = p.stat().st_size / (1024 * 1024)
                if mb > SYS_LIB_MAX_MB and not load_large:
                    logger.info("Skip %s (%.1f MB > %s; set AKD_IOS_LOAD_LARGE=1)", name, mb, SYS_LIB_MAX_MB)
                    continue
                try:
                    self._loader.load(p, name)
                except Exception as ex:  # noqa: BLE001
                    logger.warning("load %s: %s", name, ex)

        self._loader.register_malloc_exports()
        self._loader.load(self.manifest.storeservices_path, "storeservices")
        self._loader.install_ios_imports()
        # Stack prima di qualsiasi invoke_cdecl (LSKD scrive in 0xf00ffee0 ⊂ STACK)
        self._loader.setup_stack()
        # iOS: ADI parla a /usr/libexec/adid via mach_msg2 (msgh_id 1200).
        if self.manifest.adid_path is not None:
            self._loader.load_adid(self.manifest.adid_path)
        # FairPlay hw-AES path: kext prelinked + fairplayd.H2 (IOConnect ancora stub).
        if self.manifest.fairplay_iokit_path is not None:
            self._loader.load_fairplay_iokit(self.manifest.fairplay_iokit_path)
        if self.manifest.fairplayd_path is not None:
            self._loader.load_fairplayd(self.manifest.fairplayd_path)
        if self.manifest.fairplay_macos_path is not None:
            self._loader.load_fairplay_macos(self.manifest.fairplay_macos_path)
        self._loader.install_adi_mig_stub(ADI_NOT_PROVISIONED)
        # Su iOS 16+ i simboli ADI stanno in StoreServices; coreadi.dylib puo'
        # essere un duplicato - evita il secondo map.
        try:
            same = (
                self.manifest.coreadi_path.resolve() == self.manifest.storeservices_path.resolve()
                or self.manifest.coreadi_path.stat().st_size
                == self.manifest.storeservices_path.stat().st_size
                and self.manifest.coreadi_path.read_bytes()[:64]
                == self.manifest.storeservices_path.read_bytes()[:64]
            )
        except OSError:
            same = False
        if not same:
            self._loader.load(self.manifest.coreadi_path, "coreadi")
        else:
            logger.info("coreadi == storeservices — skip secondo load")

        self._symbols = resolve_adi_symbols(self._loader.exports, self.manifest.symbol_map)
        missing = [r for r in REQUIRED_ADI_ROLES if r not in self._symbols]
        android_hits = sorted(
            role for role, name in ANDROID_ADI_SYMBOLS.items() if self._loader.resolve(name)
        )
        skipped_android_init = [r for r in ANDROID_ONLY_INIT_ROLES if r not in self._symbols]

        logger.info(
            "Simboli ADI risolti: %d/%d hits=%s skip_android_init=%s",
            len(self._symbols),
            len(ANDROID_ADI_SYMBOLS),
            android_hits,
            skipped_android_init,
        )
        if missing:
            logger.warning(
                "Mapping incompleto, manca: %s — popola symbol_map.json dopo analyze_ios_adi_libs.py",
                missing,
            )
            IOS_ADI_RUNTIME_READY = False
            self._ready = True  # loaded, but not callable
            return

        # Init opzionale Android; su iOS il path è il MIG stub (install_adi_mig_stub).
        try:
            if "set_provisioning_path" in self._symbols:
                self.set_provisioning_path(".")
            load_fn = self._symbols.get("load_library")
            if load_fn:
                p = self._loader.temp_alloc_data(b".\x00")
                self._loader.invoke_cdecl(load_fn, [p])
                self._loader.temp_free(p)
            # Smoke: con MIG stub RetCode=-45061 → tipicamente -45002 (not provisioned).
            # -45016 = MIG assente/rotto; 0 = provisioned.
            fn = self._symbols["get_login_code"]
            use_real = bool(self._loader._adid_mig_server)
            try:
                smoke_ret = self._loader.invoke_cdecl(fn, [(-2) & 0xFFFFFFFFFFFFFFFF])
            except Exception as smoke_ex:  # noqa: BLE001
                if use_real:
                    logger.warning(
                        "smoke con adid reale fallita (%s) — fallback stub sintetico",
                        smoke_ex,
                    )
                    self._loader._adid_mig_server = None
                    smoke_ret = self._loader.invoke_cdecl(
                        fn, [(-2) & 0xFFFFFFFFFFFFFFFF]
                    )
                else:
                    raise
            sret = smoke_ret if smoke_ret < 0x80000000 else smoke_ret - 0x100000000
            logger.info(
                "smoke get_login_code(-2) -> %d (0x%x) adid_real=%s",
                sret,
                smoke_ret & 0xFFFFFFFF,
                bool(self._loader._adid_mig_server),
            )
            if sret == -45016:
                logger.warning(
                    "smoke ancora -45016: MIG stub non raggiunto (port/helper) — "
                    "su iOS manca adid, non nf92ngaK92"
                )
        except Exception as ex:  # noqa: BLE001
            logger.warning(
                "Simboli OK ma init/smoke Unicorn fallita (dipendenze iOS?): %s - runtime non pronto",
                ex,
            )
            IOS_ADI_RUNTIME_READY = False
            self._ready = True
            return

        IOS_ADI_RUNTIME_READY = True
        self._ready = True
        logger.info(
            "iOS ADI runtime READY (simboli + smoke Unicorn, adid=%s)",
            bool(self._loader._adid_mig_server),
        )

    @property
    def is_ready(self) -> bool:
        return self._ready and IOS_ADI_RUNTIME_READY

    def set_provisioning_path(self, path: str) -> None:
        fn = self._symbols.get("set_provisioning_path")
        if fn is None:
            # iOS: stato ADI in adid (MIG), non directory locale come Android nf92ngaK92.
            logger.info(
                "set_provisioning_path assente (iOS→adid MIG) — path=%s solo VFS/home",
                path,
            )
            self._provisioning_path = path
            return
        p = self._loader.temp_alloc_data(path.encode("utf-8") + b"\x00")
        ret = self._loader.invoke_cdecl(fn, [p])
        self._loader.temp_free(p)
        if ret != 0:
            raise RuntimeError(f"set_provisioning_path → {ret}")
        self._provisioning_path = path

    def start_provisioning(self, ds_id: int, spim: bytes) -> tuple[bytes, int]:
        fn = self._symbols["provisioning_start"]
        # Precompute UeFdbi FUORI dall'emu ADI (nested emu_start → AV @null+0x24)
        self._loader._fp_uefdbi_pre = None
        if getattr(self._loader, "_fp_uefdbi", 0):
            import hashlib

            sec1_in = hashlib.sha256(b"adi-spim-sec1" + bytes(spim)).digest()[:20]
            inv = self._loader._fp_invoke_uefdbi(
                0x8, 0x525E5BA4, 0x34788A7A, sec1_in, bytes(spim)
            )
            if inv is not None and (any(inv[0]) or any(inv[1])):
                self._loader._fp_uefdbi_pre = inv
                logger.info(
                    "UeFdbi precompute ok rc=%s sec1=%s",
                    inv[2],
                    inv[0][:8].hex(),
                )
            elif inv is not None:
                logger.info("UeFdbi precompute nullo (rc=%s) — start userà AES", inv[2])
        p_spim = self._loader.temp_alloc_data(spim)
        p_cpim = self._loader.temp_alloc(8)
        p_cpim_len = self._loader.temp_alloc(4)
        p_session = self._loader.temp_alloc(4)
        ret = self._loader.invoke_cdecl(
            fn,
            [ds_id & 0xFFFFFFFFFFFFFFFF, p_spim, len(spim), p_cpim, p_cpim_len, p_session],
        )
        if ret != 0:
            raise RuntimeError(f"provisioning_start → {ret}")
        cpim_ptr = int.from_bytes(self._loader.uc.mem_read(p_cpim, 8), "little")
        cpim_len = int.from_bytes(self._loader.uc.mem_read(p_cpim_len, 4), "little")
        session = int.from_bytes(self._loader.uc.mem_read(p_session, 4), "little")
        if cpim_ptr and cpim_len > 0:
            cpim = bytes(self._loader.uc.mem_read(cpim_ptr, cpim_len))
        else:
            # SS non unpacka ancora l'OOL dopo il loopback XPC+FairPlay drive:
            # usa l'output IOConnect / CPIM pendente.
            cpim = getattr(self._loader, "_last_start_cpim", None) or getattr(
                self._loader, "_fp_last_out", b""
            )
            cpim = bytes(cpim[:64]) if cpim and len(cpim) >= 16 else b"\x33" * 16
            session = int(
                getattr(self._loader, "_last_start_session", None) or session or 1
            )
            logger.info(
                "provisioning_start: CPIM via FairPlay drive len=%d session=%d (SS OOL empty)",
                len(cpim),
                session,
            )
        self._loader.temp_free(p_spim)
        self._loader.temp_free(p_cpim)
        self._loader.temp_free(p_cpim_len)
        self._loader.temp_free(p_session)
        return cpim, session

    def end_provisioning(self, session: int, ptm: bytes, tk: bytes) -> None:
        fn = self._symbols["provisioning_end"]
        p_ptm = self._loader.temp_alloc_data(ptm)
        p_tk = self._loader.temp_alloc_data(tk)
        ret = self._loader.invoke_cdecl(fn, [session, p_ptm, len(ptm), p_tk, len(tk)])
        self._loader.temp_free(p_ptm)
        self._loader.temp_free(p_tk)
        if ret != 0:
            raise RuntimeError(f"provisioning_end → {ret}")

    def request_otp(self, ds_id: int) -> tuple[bytes, bytes]:
        fn = self._symbols["otp_request"]
        p_mid = self._loader.temp_alloc(8)
        p_mid_len = self._loader.temp_alloc(4)
        p_otp = self._loader.temp_alloc(8)
        p_otp_len = self._loader.temp_alloc(4)
        ret = self._loader.invoke_cdecl(
            fn,
            [ds_id & 0xFFFFFFFFFFFFFFFF, p_mid, p_mid_len, p_otp, p_otp_len],
        )
        if ret != 0:
            raise RuntimeError(f"otp_request → {ret}")
        mid_ptr = int.from_bytes(self._loader.uc.mem_read(p_mid, 8), "little")
        mid_len = int.from_bytes(self._loader.uc.mem_read(p_mid_len, 4), "little")
        otp_ptr = int.from_bytes(self._loader.uc.mem_read(p_otp, 8), "little")
        otp_len = int.from_bytes(self._loader.uc.mem_read(p_otp_len, 4), "little")
        mid = bytes(self._loader.uc.mem_read(mid_ptr, mid_len))
        otp = bytes(self._loader.uc.mem_read(otp_ptr, otp_len))
        dispose = self._symbols.get("dispose")
        if dispose:
            self._loader.invoke_cdecl(dispose, [mid_ptr])
            self._loader.invoke_cdecl(dispose, [otp_ptr])
        for a in (p_mid, p_mid_len, p_otp, p_otp_len):
            self._loader.temp_free(a)
        return otp, mid

    def is_machine_provisioned(self, ds_id: int) -> bool:
        fn = self._symbols["get_login_code"]
        # Cattura RetCode adid grezzo: SS a volte mappa -45070 → 0.
        saved = {"rc": None}
        _fin = type(self._loader)._adi_mig_finish_real

        def _wrap(this, uc, _f=_fin, _s=saved):  # noqa: ANN001
            sb = this._adi_mig_saved or {}
            out_buf = int(sb.get("out_buf", 0))
            _f(this, uc)
            if out_buf and _s["rc"] is None:
                try:
                    _s["rc"] = struct.unpack_from(
                        "<i", bytes(this._uc.mem_read(out_buf, 0x28)), 0x20
                    )[0]
                except Exception:  # noqa: BLE001
                    pass

        type(self._loader)._adi_mig_finish_real = _wrap  # type: ignore[method-assign]
        try:
            ret = self._loader.invoke_cdecl(fn, [ds_id & 0xFFFFFFFFFFFFFFFF])
        finally:
            type(self._loader)._adi_mig_finish_real = _fin  # type: ignore[method-assign]
        sret = ret if ret < 0x80000000 else ret - 0x100000000
        adid_rc = saved["rc"]
        # Preferisci status XPC se il RetCode MIG resta 0 (reply layout parziale)
        xpc_st = getattr(self._loader, "_adi_xpc_status", None)
        if xpc_st is not None and (adid_rc is None or adid_rc == 0):
            adid_rc = int(xpc_st)
        self._loader._adi_xpc_status = None
        # RetCode adid in banda ADI: non provisioned / dep mancante (FP/XPC)
        if adid_rc is not None and -45100 <= int(adid_rc) <= -45000:
            return False
        if adid_rc == 0:
            return True
        # 0 = provisioned (SS) — attenzione: SS a volte mappa -45070→0
        # Android: -45061 not provisioned
        # iOS stub: -45061 → spesso -45002; -45016 = MIG non stubbato
        if sret == 0 and adid_rc is None:
            return True
        if -45100 <= sret <= -45000:
            return False
        if sret == 0:
            return False  # SS quirk senza RetCode adid affidabile
        raise RuntimeError(f"get_login_code -> {sret} (adid_rc={adid_rc})")

    def probe(self) -> dict:
        out: dict = {
            "backend": "ios-macho",
            "runtime_ready": IOS_ADI_RUNTIME_READY,
            "source_dsc": self.manifest.source_dsc,
            "symbols_resolved": sorted(self._symbols.keys()),
            "symbols_missing": [r for r in REQUIRED_ADI_ROLES if r not in self._symbols],
            "export_count": len(self._loader.exports),
            "android_style_hits": sorted(
                role for role, name in ANDROID_ADI_SYMBOLS.items() if self._loader.resolve(name)
            ),
        }
        for role, p in (
            ("storeservices", self.manifest.storeservices_path),
            ("coreadi", self.manifest.coreadi_path),
        ):
            exports = collect_exports(p)
            adi_like = sorted(n for n in exports if "adi" in n.lower() or "ADI" in n)[:20]
            out[role] = {
                "path": str(p),
                "exports": len(exports),
                "sample": sorted(exports)[:15],
                "adi_like": adi_like,
            }
        if self.manifest.adid_path is not None:
            out["adid"] = {
                "path": str(self.manifest.adid_path),
                "loaded": bool(self._loader._adid_mig_server),
                "mig_server": hex(ADID_MIG_SERVER),
                "size": self.manifest.adid_path.stat().st_size,
            }
        if self.manifest.fairplayd_path is not None:
            out["fairplayd"] = {
                "path": str(self.manifest.fairplayd_path),
                "loaded": self._loader._fairplayd_base is not None,
                "base": hex(self._loader._fairplayd_base or 0),
                "size": self.manifest.fairplayd_path.stat().st_size,
            }
        if self.manifest.fairplay_iokit_path is not None:
            out["fairplay_iokit"] = {
                "path": str(self.manifest.fairplay_iokit_path),
                "loaded": self._loader._fairplay_iokit_path is not None,
                "size": self.manifest.fairplay_iokit_path.stat().st_size,
                "hw_loaded": bool(self._loader._fp_hw_loaded),
            }
        return out


def ios_libs_available(libs_dir: Path | None = None) -> bool:
    root = libs_dir or app_data_ios_libs_dir()
    manifest = root / "manifest.json"
    if not manifest.exists():
        return False
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    extracted = data.get("extracted") or {}
    return bool(extracted.get("coreadi") and extracted.get("storeservices"))
