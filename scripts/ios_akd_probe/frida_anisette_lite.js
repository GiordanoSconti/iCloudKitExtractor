// Lightweight anisette + MD-LU recovery attempts.
// python fetch_anisette.py -H IP --lite   (default target: akd)

var ANISETTE_MARKER = "__ANISETTE_JSON__";

function emit(payload) {
  try { send(payload); } catch (_) {}
  console.log(ANISETTE_MARKER + JSON.stringify(payload));
}

function findExport(modNames, sym) {
  for (let i = 0; i < modNames.length; i++) {
    try {
      const m = Process.findModuleByName(modNames[i]);
      if (!m) continue;
      const p = m.findExportByName ? m.findExportByName(sym) : m.getExportByName(sym);
      if (p) return p;
    } catch (_) {}
  }
  try {
    if (Module.findGlobalExportByName) return Module.findGlobalExportByName(sym);
  } catch (_) {}
  return null;
}

function msgSendId0(obj, selName) {
  try {
    const sel = ObjC.selector(selName);
    let sendPtr = findExport(["libobjc.A.dylib"], "objc_msgSend");
    if (!sendPtr) {
      try { sendPtr = Module.getGlobalExportByName("objc_msgSend"); } catch (_) {}
    }
    const r = new NativeFunction(sendPtr, "pointer", ["pointer", "pointer"])(obj.handle, sel);
    if (!r || r.isNull()) return null;
    const o = new ObjC.Object(r);
    return o.isNull() ? null : o.toString();
  } catch (_) {
    return null;
  }
}

function msgSendVoid0(obj, selName) {
  const sel = ObjC.selector(selName);
  let sendPtr = findExport(["libobjc.A.dylib"], "objc_msgSend");
  if (!sendPtr) {
    try { sendPtr = Module.getGlobalExportByName("objc_msgSend"); } catch (_) {}
  }
  new NativeFunction(sendPtr, "void", ["pointer", "pointer"])(obj.handle, sel);
}

function sha256HexUtf8(str, upper) {
  if (!str) return null;
  const ns = ObjC.classes.NSString.stringWithString_(String(str));
  const data = ns.dataUsingEncoding_(4);
  const len = Number(data.length());
  const outPtr = Memory.alloc(32);
  const sym = findExport(["libcommonCrypto.dylib", "libSystem.B.dylib"], "CC_SHA256");
  if (!sym) return null;
  new NativeFunction(sym, "pointer", ["pointer", "ulong", "pointer"])(ptr(data.bytes()), len, outPtr);
  const bytes = new Uint8Array(outPtr.readByteArray(32));
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    const h = ("0" + bytes[i].toString(16)).slice(-2);
    hex += upper ? h.toUpperCase() : h;
  }
  return hex;
}

function looksUuid(s) {
  if (!s || typeof s !== "string") return false;
  if (s.indexOf("err:") === 0 || s.indexOf("TypeError") >= 0) return false;
  // 8-4-4-4-12 or 32/64 hex
  if (/^[0-9a-fA-F-]{36}$/.test(s)) return true;
  if (/^[0-9a-fA-F]{32}$/.test(s)) return true;
  if (/^[0-9a-fA-F]{64}$/.test(s)) return true;
  return s.length >= 16 && s.length <= 64;
}

function dictGet(dict, key) {
  if (!dict || dict.isNull()) return null;
  try {
    const v = dict.objectForKey_(key);
    return v && !v.isNull() ? v.toString() : null;
  } catch (_) {
    return null;
  }
}

function plistScan() {
  const found = [];
  const paths = [
    "/var/mobile/Library/Preferences/com.apple.AuthKit.plist",
    "/var/mobile/Library/Preferences/com.apple.authkit.plist",
    "/var/mobile/Library/Preferences/com.apple.accountsd.plist",
    "/var/mobile/Library/Preferences/com.apple.cmw.deepmapcache.plist",
    "/var/mobile/Library/Preferences/com.apple.identityservices.idstatuscache.plist",
    "/var/root/Library/Preferences/com.apple.AuthKit.plist",
  ];
  const NSDictionary = ObjC.classes.NSDictionary;
  for (let i = 0; i < paths.length; i++) {
    try {
      const d = NSDictionary.dictionaryWithContentsOfFile_(paths[i]);
      if (!d || d.isNull()) continue;
      const keys = d.allKeys();
      const n = Number(keys.count());
      for (let k = 0; k < n; k++) {
        const key = keys.objectAtIndex_(k).toString();
        if (!/uuid|UUID|localUser|LocalUser|MD-LU|anisette|ADI/i.test(key)) continue;
        const val = d.objectForKey_(key);
        found.push({
          path: paths[i],
          key: key,
          value: val && !val.isNull() ? val.toString().slice(0, 120) : null,
        });
      }
    } catch (_) {}
  }
  return found;
}

function tryAnisette() {
  if (typeof ObjC === "undefined" || !ObjC.available) {
    emit({ ok: false, error: "ObjC missing" });
    return;
  }

  const path = "/System/Library/PrivateFrameworks/AuthKit.framework";
  const bundle = ObjC.classes.NSBundle.bundleWithPath_(path);
  if (bundle && !bundle.isLoaded()) bundle.load();

  const Ctrl = ObjC.classes.AKAnisetteProvisioningController;
  if (!Ctrl) {
    emit({ ok: false, error: "no AKAnisetteProvisioningController" });
    return;
  }

  const ctrl = Ctrl.alloc().init();
  const errPtr = Memory.alloc(Process.pointerSize);
  errPtr.writePointer(ptr(0));
  let data;
  try {
    data = ctrl.anisetteDataWithError_(errPtr);
  } catch (e) {
    emit({ ok: false, error: "anisette: " + e });
    return;
  }
  if (!data) {
    emit({ ok: false, error: "anisette nil" });
    return;
  }
  data = new ObjC.Object(data);

  function asStr(v) {
    if (v === null || v === undefined) return null;
    try {
      const o = new ObjC.Object(v);
      return o.isNull() ? null : o.toString();
    } catch (_) {
      return String(v);
    }
  }

  const mid = asStr(data.machineID());
  const otp = asStr(data.oneTimePassword());
  let rinfo = "";
  try { rinfo = String(data.routingInfo()); } catch (_) {}

  let deviceId = null;
  let clientInfo = null;
  let localUserUuid = null;
  let mdLu = null;
  let how = null;
  const uuidCandidates = {};

  try {
    const dev = ObjC.classes.AKDevice.currentDevice();
    const sels = [
      "uniqueDeviceIdentifier",
      "serverFriendlyDescription",
      "localUserUUID",
      "_volumeGroupUUID",
      "serialNumber",
      "integratedCircuitCardIdentifier",
    ];
    for (let i = 0; i < sels.length; i++) {
      uuidCandidates[sels[i]] = msgSendId0(dev, sels[i]);
    }
    deviceId = uuidCandidates.uniqueDeviceIdentifier;
    clientInfo = uuidCandidates.serverFriendlyDescription;
    localUserUuid = uuidCandidates.localUserUUID;
    if (!localUserUuid && looksUuid(uuidCandidates._volumeGroupUUID)) {
      localUserUuid = uuidCandidates._volumeGroupUUID;
      uuidCandidates._used = "_volumeGroupUUID";
    }
  } catch (e) {
    uuidCandidates._devErr = String(e);
  }

  // Class helper headers
  try {
    const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    if (NSMutableURLRequest && NSMutableURLRequest.ak_anisetteHeadersWithData_) {
      const hdrs = NSMutableURLRequest.ak_anisetteHeadersWithData_(data);
      mdLu = dictGet(hdrs, "X-Apple-I-MD-LU") || dictGet(hdrs, "X-Apple-MD-LU");
      if (mdLu) how = "ak_anisetteHeadersWithData:";
      if (!clientInfo) clientInfo = dictGet(hdrs, "X-MMe-Client-Info");
      if (!deviceId) deviceId = dictGet(hdrs, "X-Mme-Device-Id");
    }
  } catch (_) {}

  // Force LU header onto a request
  if (!mdLu) {
    try {
      const req = ObjC.classes.NSMutableURLRequest.requestWithURL_(
        ObjC.classes.NSURL.URLWithString_("https://gsa.apple.com/")
      );
      const adders = [
        "ak_addLocalUserUUIDHashHeader",
        "ak_addAnisetteHeaders",
      ];
      for (let i = 0; i < adders.length; i++) {
        try {
          if (req.respondsToSelector_(ObjC.selector(adders[i]))) {
            msgSendVoid0(req, adders[i]);
          }
        } catch (_) {}
      }
      const fields = req.allHTTPHeaderFields();
      mdLu = dictGet(fields, "X-Apple-I-MD-LU") || dictGet(fields, "X-Apple-MD-LU");
      if (mdLu) how = "ak_addLocalUserUUIDHashHeader";
    } catch (_) {}
  }

  // Hash UUID (Apple / xtool style). Prefer lowercase; also try uppercase.
  if (!mdLu && looksUuid(localUserUuid)) {
    mdLu = sha256HexUtf8(localUserUuid, false);
    how = "sha256(localUserUUID).lower";
    if (!mdLu) {
      mdLu = sha256HexUtf8(localUserUuid, true);
      how = "sha256(localUserUUID).upper";
    }
    // also try without dashes
    if (!mdLu) {
      const compact = String(localUserUuid).replace(/-/g, "");
      mdLu = sha256HexUtf8(compact, false);
      how = "sha256(uuid-nodash).lower";
    }
  }

  const plists = plistScan();
  // If plist had a UUID-like value under localUser*, hash it
  if (!mdLu) {
    for (let i = 0; i < plists.length; i++) {
      const v = plists[i].value;
      if (looksUuid(v) && /localUser|UUID/i.test(plists[i].key)) {
        localUserUuid = v;
        mdLu = sha256HexUtf8(v, false);
        how = "sha256(plist:" + plists[i].key + ")";
        break;
      }
    }
  }

  emit({
    ok: true,
    frida: Frida.version,
    "X-Apple-I-MD-M": mid,
    "X-Apple-I-MD": otp,
    "X-Apple-I-MD-RINFO": rinfo,
    "X-Apple-I-MD-LU": mdLu,
    "X-Mme-Device-Id": deviceId,
    "X-MMe-Client-Info": clientInfo,
    localUserUUID: localUserUuid,
    _lu_how: how,
    _uuid_candidates: uuidCandidates,
    _plist_hits: plists,
  });
}

tryAnisette();
