#!/usr/bin/env python3
"""
Anisette HTTP server che emula il flusso interno iPhone/akd (EPB-like).

- MidService provisioning con header akd (Anisette.py ProvisioningSession)
- ADI via emulazione ARM64 Unicorn (lib Apple Music)
- Identità device: com.apple.akd / iPhone9,3 / MD-RINFO 17106176

Compatibile con RemoteAnisetteProvider (GET / JSON).

Uso:
  python ios_akd_server.py
  python ios_akd_server.py --port 6971 --reset
"""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import shutil
import sys
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from anisette import Anisette
from anisette._device import AnisetteDeviceConfig

# Allineato a AppleClientInfo.AuthKitIphoneClientInfo (C#)
IPHONE_AKD_CLIENT_INFO = (
    "<iPhone9,3> <iPhone OS;12.4.1;16G102> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)
IOS_MD_RINFO = "17106176"
DEFAULT_PORT = 6971


def default_data_dir() -> Path:
    appdata = Path.home() / "AppData" / "Roaming" / "iCloudKitExtractor" / "anisette-py-ios"
    if sys.platform != "win32":
        appdata = Path.home() / ".config" / "iCloudKitExtractor" / "anisette-py-ios"
    return appdata


def generate_ios_serial() -> str:
    alphabet = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    chars = ["F", str(secrets.randbelow(8) + 2), chr(ord("A") + secrets.randbelow(26))]
    chars += [alphabet[secrets.randbelow(len(alphabet))] for _ in range(9)]
    return "".join(chars)


def make_device_config(serial: str) -> AnisetteDeviceConfig:
    return AnisetteDeviceConfig(
        server_friendly_description=IPHONE_AKD_CLIENT_INFO,
        unique_device_id=str(uuid.uuid4()).upper(),
        adi_id=secrets.token_hex(8).lower(),
        # 64 hex minuscoli = formato MD-LU iOS reale (EPB akd)
        local_user_uuid=secrets.token_hex(32),
    )


def load_or_create_session(data_dir: Path, reset: bool) -> tuple[Anisette, str, str]:
    data_dir.mkdir(parents=True, exist_ok=True)
    libs_path = data_dir / "libs.bin"
    prov_path = data_dir / "session.prov"
    meta_path = data_dir / "meta.json"

    if reset and data_dir.exists():
        shutil.rmtree(data_dir, ignore_errors=True)
        data_dir.mkdir(parents=True, exist_ok=True)

    serial = generate_ios_serial()
    meta: dict = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            serial = meta.get("serialNumber", serial)
        except (json.JSONDecodeError, OSError):
            meta = {}

    if prov_path.exists() and libs_path.exists():
        ani = Anisette.load(libs_path, prov_path)
        md_lu = ani._ani_provider.device.local_user_uuid  # noqa: SLF001
        return ani, serial, md_lu

    device_cfg = make_device_config(serial)
    if libs_path.exists():
        ani = Anisette.init(libs_path, default_device_config=device_cfg)
    else:
        ani = Anisette.init(default_device_config=device_cfg)
        ani.save_libs(libs_path)

    md_lu = ani._ani_provider.device.local_user_uuid  # noqa: SLF001
    meta_path.write_text(
        json.dumps(
            {
                "profile": "ios-akd",
                "clientInfo": IPHONE_AKD_CLIENT_INFO,
                "serialNumber": serial,
                "mdLu": md_lu,
                "deviceUuid": ani._ani_provider.device.unique_device_identifier,  # noqa: SLF001
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return ani, serial, md_lu


def build_headers(ani: Anisette, serial: str, md_lu: str) -> dict[str, str]:
    ani.provision()
    otp = ani._ani_provider.adi.request_otp(-2)  # noqa: SLF001
    device = ani._ani_provider.device  # noqa: SLF001
    import base64

    now = datetime.now(timezone.utc).replace(microsecond=0)
    tz = datetime.now(timezone.utc).strftime("%Z") or "UTC"
    if tz in ("ora legale Europa occidentale", "ora solare Europa occidentale"):
        tz = "W. Europe Standard Time"
    locale_name = "en_US"

    return {
        "X-Apple-I-Client-Time": now.isoformat().replace("+00:00", "Z"),
        "X-Apple-I-MD": base64.b64encode(bytes(otp.otp)).decode(),
        "X-Apple-I-MD-LU": md_lu,
        "X-Apple-I-MD-M": base64.b64encode(bytes(otp.machine_id)).decode(),
        "X-Apple-I-MD-RINFO": IOS_MD_RINFO,
        "X-Apple-I-SRL-NO": serial,
        "X-Apple-I-TimeZone": tz,
        "X-Apple-Locale": locale_name,
        "X-MMe-Client-Info": device.server_friendly_description,
        "X-Mme-Device-Id": device.unique_device_identifier,
        "serialNumber": serial,
        "clientProductType": "iPhone9,3",
        "locale": locale_name,
        "timeZone": tz,
        "countryCode": "US",
    }


def save_session(ani: Anisette, data_dir: Path) -> None:
    ani.save_provisioning(data_dir / "session.prov")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Anisette iPhone/akd emulated server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--reset", action="store_true", help="Cancella sessione e ri-provisiona")
    args = parser.parse_args()

    data_dir = args.data_dir or default_data_dir()
    logging.info("Data dir: %s", data_dir)
    logging.info("Provisioning (emulated ARM ADI + MidService akd)…")

    ani, serial, md_lu = load_or_create_session(data_dir, args.reset)
    save_session(ani, data_dir)

    sample = build_headers(ani, serial, md_lu)
    logging.info("MD-M prefix: %s…", sample["X-Apple-I-MD-M"][:16])
    logging.info("Client-Info: %s", sample["X-MMe-Client-Info"][:60])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *fargs) -> None:  # noqa: ANN001
            logging.debug(fmt, *fargs)

        def do_GET(self) -> None:  # noqa: N802
            if self.path not in ("/", "/health", ""):
                self.send_error(404)
                return
            try:
                headers = build_headers(ani, serial, md_lu)
                save_session(ani, data_dir)
                body = json.dumps(headers).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Implementation-Version", "iCloudKitExtractor-ios-akd/1")
                self.end_headers()
                self.wfile.write(body)
            except Exception as ex:  # noqa: BLE001
                logging.exception("GET failed")
                self.send_error(500, str(ex))

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/provision":
                self.send_error(404)
                return
            nonlocal ani, serial, md_lu
            shutil.rmtree(data_dir, ignore_errors=True)
            data_dir.mkdir(parents=True, exist_ok=True)
            ani, serial, md_lu = load_or_create_session(data_dir, reset=True)
            save_session(ani, data_dir)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true,"profile":"ios-akd"}')

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    logging.info("iOS akd anisette — http://%s:%s/", args.host, args.port)
    logging.info("Configura anisette.json: serverUrl + authMode iphone")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
