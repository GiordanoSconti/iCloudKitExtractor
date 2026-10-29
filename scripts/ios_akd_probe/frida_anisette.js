// python -m frida_tools.repl -H IP:27042 -n akd -l frida_anisette.js
// python fetch_anisette.py -H IP:27042 --lite

var ANISETTE_MARKER = "__ANISETTE_JSON__";

function bytesToBase64(p, length) {
  p = ptr(p);
  if (p.isNull() || !length || length <= 0) return "";
  const buf = p.readByteArray(length);
  if (!buf) return "";
  const bytes = new Uint8Array(buf);
  const tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (a << 16) | (b << 8) | c;
    out += tab[(n >> 18) & 63];
    out += tab[(n >> 12) & 63];
    out += i + 1 < bytes.length ? tab[(n >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? tab[n & 63] : "=";
  }
  return out;
}

function asNumber(v) {
  if (v === null || v === undefined) return 0;
  if (typeof v === "number") return v;
  if (typeof v === "bigint") return Number(v);
  try {
    if (typeof v === "object" && v !== null && typeof v.valueOf === "function") {
      const x = v.valueOf();
      if (typeof x === "number") return x;
      if (typeof x === "bigint") return Number(x);
    }
  } catch (_) {}
  const n = parseInt(String(v), 10);
  return Number.isFinite(n) ? n : 0;
}

function findExport(modNames, sym) {
  for (let i = 0; i < modNames.length; i++) {
    try {
      const m = Process.findModuleByName(modNames[i]);
      if (!m) continue;
      const p = m.findExportByName
        ? m.findExportByName(sym)
        : m.getExportByName(sym);
      if (p) return p;
    } catch (_) {}
  }
  try {
    if (typeof Module.findGlobalExportByName === "function") {
      return Module.findGlobalExportByName(sym);
    }
  } catch (_) {}
  try {
    if (typeof Module.getGlobalExportByName === "function") {
      return Module.getGlobalExportByName(sym);
    }
  } catch (_) {}
  return null;
}

// X-Apple-I-MD-LU = SHA-256(UTF-8 of AKDevice.localUserUUID) as lowercase hex (64 chars)
function sha256HexUtf8(str) {
  if (!str) return null;
  const ns = ObjC.classes.NSString.stringWithString_(String(str));
  const data = ns.dataUsingEncoding_(4); // NSUTF8StringEncoding
  if (!data || data.isNull()) return null;
  const len = asNumber(data.length());
  const inPtr = data.bytes();
  const outPtr = Memory.alloc(32);
  const sym = findExport(
    ["libcommonCrypto.dylib", "libSystem.B.dylib", "libcorecrypto.dylib"],
    "CC_SHA256"
  );
  if (!sym) return null;
  const CC_SHA256 = new NativeFunction(sym, "pointer", ["pointer", "ulong", "pointer"]);
  CC_SHA256(ptr(inPtr), len, outPtr);
  const bytes = new Uint8Array(outPtr.readByteArray(32));
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += ("0" + bytes[i].toString(16)).slice(-2);
  }
  return hex;
}

function headerFromDict(dict, key) {
  if (!dict || dict.isNull()) return null;
  try {
    const v = dict.objectForKey_(key);
    if (v && !v.isNull()) return v.toString();
  } catch (_) {}
  return null;
}

function nsDictToObject(dict) {
  const out = {};
  if (!dict || dict.isNull()) return out;
  try {
    const keys = dict.allKeys();
    const n = asNumber(keys.count());
    for (let i = 0; i < n; i++) {
      const k = keys.objectAtIndex_(i).toString();
      out[k] = dict.objectForKey_(k).toString();
    }
  } catch (_) {}
  return out;
}

function listMethodsMatching(klass, re) {
  const out = [];
  try {
    const methods = klass.$ownMethods || [];
    for (let i = 0; i < methods.length; i++) {
      const m = String(methods[i]);
      if (re.test(m)) out.push(m);
    }
  } catch (_) {}
  return out;
}

function objcMsgSendPtr() {
  let sendPtr = findExport(["libobjc.A.dylib"], "objc_msgSend");
  if (!sendPtr) {
    try {
      sendPtr = Module.getGlobalExportByName("objc_msgSend");
    } catch (_) {}
  }
  if (!sendPtr) throw new Error("objc_msgSend not found");
  return sendPtr;
}

function msgSendVoid0(obj, selName) {
  const sel = ObjC.selector(selName);
  const objc_msgSend = new NativeFunction(objcMsgSendPtr(), "void", ["pointer", "pointer"]);
  objc_msgSend(obj.handle, sel);
}

function msgSendId0(obj, selName) {
  const sel = ObjC.selector(selName);
  const objc_msgSend = new NativeFunction(objcMsgSendPtr(), "pointer", ["pointer", "pointer"]);
  const r = objc_msgSend(obj.handle, sel);
  if (!r || r.isNull()) return null;
  try {
    const o = new ObjC.Object(r);
    if (o.isNull()) return null;
    return o.toString();
  } catch (_) {
    return null;
  }
}

function isRealUuid(s) {
  if (!s || typeof s !== "string") return false;
  if (s.indexOf("err:") === 0) return false;
  // UUID or hex-ish identity
  return s.length >= 8 && s.indexOf("TypeError") < 0;
}

function mdLuFromAnisetteHeadersDict(anisetteData) {
  const info = { how: null, err: null, headers: null, akMethods: [] };
  try {
    const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    if (!NSMutableURLRequest) {
      info.err = "no NSMutableURLRequest";
      return { mdLu: null, info: info };
    }
    info.akMethods = listMethodsMatching(NSMutableURLRequest, /ak_/);

    // Class method: +ak_anisetteHeadersWithData:
    try {
      if (NSMutableURLRequest.ak_anisetteHeadersWithData_) {
        const dict = NSMutableURLRequest.ak_anisetteHeadersWithData_(anisetteData);
        info.headers = nsDictToObject(dict);
        const mdLu =
          info.headers["X-Apple-I-MD-LU"] ||
          info.headers["X-Apple-MD-LU"] ||
          null;
        if (mdLu) {
          info.how = "ak_anisetteHeadersWithData:";
          return { mdLu: mdLu, info: info };
        }
      }
    } catch (e) {
      info.err = "ak_anisetteHeadersWithData_: " + e;
    }

    // Instance: add LU hash (and optionally full anisette) via objc_msgSend
    try {
      const NSURL = ObjC.classes.NSURL;
      const url = NSURL.URLWithString_("https://gsa.apple.com/");
      const req = NSMutableURLRequest.requestWithURL_(url);
      const candidates = [
        "ak_addLocalUserUUIDHashHeader",
        "ak_addAnisetteHeaders",
        "ak_addClientInfoHeader",
        "ak_addDeviceUDIDHeader",
      ];
      const called = [];
      for (let i = 0; i < candidates.length; i++) {
        const selName = candidates[i];
        try {
          if (req.respondsToSelector_(ObjC.selector(selName))) {
            msgSendVoid0(req, selName);
            called.push(selName);
          }
        } catch (e) {
          info.err = selName + ": " + e;
        }
      }
      const fields = req.allHTTPHeaderFields();
      info.headers = nsDictToObject(fields);
      info.how = called.length ? "msgSend:" + called.join("+") : info.how;
      const mdLu =
        info.headers["X-Apple-I-MD-LU"] ||
        info.headers["X-Apple-MD-LU"] ||
        null;
      if (mdLu) return { mdLu: mdLu, info: info };
    } catch (e) {
      info.err = "request path: " + e;
    }

    return { mdLu: null, info: info };
  } catch (e) {
    info.err = String(e);
    return { mdLu: null, info: info };
  }
}

function listAkDeviceUserSelectors() {
  try {
    return listMethodsMatching(ObjC.classes.AKDevice, /user|uuid|UUID|local|LU|hash|volume/i);
  } catch (_) {
    return [];
  }
}

function tryReadLocalUserUuid(dev) {
  const names = ["localUserUUID", "localUserId", "_volumeGroupUUID"];
  const tried = {};
  for (let i = 0; i < names.length; i++) {
    const sel = names[i];
    // 1) Frida sugar
    try {
      const v = dev[sel]();
      if (v === null || v === undefined) {
        tried[sel + ".sugar"] = null;
      } else {
        const o = new ObjC.Object(v);
        tried[sel + ".sugar"] = o.isNull() ? null : o.toString();
      }
    } catch (e) {
      tried[sel + ".sugar"] = "err:" + e;
    }
    // 2) objc_msgSend (needed when sugar says "not a function")
    try {
      tried[sel + ".msgSend"] = msgSendId0(dev, sel);
    } catch (e) {
      tried[sel + ".msgSend"] = "err:" + e;
    }
  }
  return tried;
}

function pickBestUuid(tried) {
  if (!tried) return null;
  const keys = Object.keys(tried);
  for (let i = 0; i < keys.length; i++) {
    const v = tried[keys[i]];
    if (isRealUuid(v)) return v;
  }
  return null;
}

function coerceToB64(value) {
  const diag = { className: null, len: null, how: null, err: null };
  if (value === null || value === undefined) {
    diag.err = "null";
    return { b64: "", diag: diag };
  }

  let obj;
  try {
    obj = new ObjC.Object(value);
  } catch (e) {
    diag.err = "not ObjC: " + e;
    return { b64: "", diag: diag };
  }
  if (obj.isNull()) {
    diag.err = "nil";
    return { b64: "", diag: diag };
  }

  try {
    diag.className = obj.$className;
  } catch (_) {}

  // NSString (already text / already b64)
  try {
    if (ObjC.classes.NSString && obj.isKindOfClass_(ObjC.classes.NSString)) {
      diag.how = "NSString";
      return { b64: obj.toString(), diag: diag };
    }
  } catch (_) {}

  // NSData — try several Frida ObjC call styles
  const tryB64Selector = function () {
    const attempts = [
      function () { return obj.base64EncodedStringWithOptions_(0); },
      function () { return obj["base64EncodedStringWithOptions:"](0); },
      function () { return obj["- base64EncodedStringWithOptions:"](0); },
    ];
    for (let i = 0; i < attempts.length; i++) {
      try {
        const s = attempts[i]();
        if (s) return s.toString();
      } catch (_) {}
    }
    return null;
  };

  try {
    const viaSel = tryB64Selector();
    if (viaSel) {
      diag.how = "base64EncodedStringWithOptions";
      return { b64: viaSel, diag: diag };
    }
  } catch (e) {
    diag.err = "sel: " + e;
  }

  // Raw bytes
  try {
    const len = asNumber(obj.length());
    diag.len = len;
    const raw = obj.bytes();
    if (raw && len > 0) {
      const b64 = bytesToBase64(raw, len);
      if (b64) {
        diag.how = "bytes";
        return { b64: b64, diag: diag };
      }
    }
  } catch (e) {
    diag.err = "bytes: " + e;
  }

  // Last resort
  try {
    const t = obj.toString();
    if (t && t.indexOf(diag.className || "___") === -1) {
      diag.how = "toString";
      return { b64: t, diag: diag };
    }
  } catch (_) {}

  if (!diag.err) diag.err = "unconverted";
  return { b64: "", diag: diag };
}

function emit(payload) {
  try {
    send(payload);
  } catch (_) {}
  console.log(ANISETTE_MARKER + JSON.stringify(payload));
}

function tryAnisette() {
  if (typeof ObjC === "undefined" || !ObjC.available) {
    emit({
      ok: false,
      error: "ObjC bridge missing (use frida_tools.repl / fetch_anisette.py)",
    });
    return;
  }

  const path = "/System/Library/PrivateFrameworks/AuthKit.framework";
  const bundle = ObjC.classes.NSBundle.bundleWithPath_(path);
  if (bundle !== null && !bundle.isLoaded()) {
    if (!bundle.load()) {
      emit({ ok: false, error: "NSBundle load AuthKit failed" });
      return;
    }
  }

  const Ctrl = ObjC.classes.AKAnisetteProvisioningController;
  if (!Ctrl) {
    emit({ ok: false, error: "AKAnisetteProvisioningController missing" });
    return;
  }

  const ctrl = Ctrl.alloc().init();
  const errPtr = Memory.alloc(Process.pointerSize);
  errPtr.writePointer(ptr(0));

  let data;
  try {
    data = ctrl.anisetteDataWithError_(errPtr);
  } catch (e) {
    emit({ ok: false, error: "call failed: " + e });
    return;
  }

  if (data === null || data === undefined) {
    const errNative = errPtr.readPointer();
    const err = errNative.isNull() ? null : new ObjC.Object(errNative);
    emit({
      ok: false,
      error: err ? String(err) : "anisetteDataWithError returned nil",
    });
    return;
  }

  data = new ObjC.Object(data);

  // Property names vary across iOS / AuthKit builds
  function pick(obj, names) {
    for (let i = 0; i < names.length; i++) {
      try {
        const v = obj[names[i]]();
        if (v !== null && v !== undefined) return v;
      } catch (_) {}
    }
    return null;
  }

  function strOrNull(v) {
    if (v === null || v === undefined) return null;
    try {
      const o = new ObjC.Object(v);
      if (o.isNull()) return null;
      return o.toString();
    } catch (_) {
      try {
        return String(v);
      } catch (__) {
        return null;
      }
    }
  }

  let deviceId = null;
  let clientInfo = null;
  let localUserUuid = null; // raw UUID string from AuthKit
  let mdLu = null;          // X-Apple-I-MD-LU = SHA256(uuid) hex
  let productModel = null;
  let uuidTried = null;
  try {
    const AKDevice = ObjC.classes.AKDevice;
    if (AKDevice) {
      const dev = AKDevice.currentDevice();
      deviceId = strOrNull(pick(dev, [
        "uniqueDeviceIdentifier",
        "uniqueDeviceID",
        "deviceIdentity",
      ]));
      // Usually the exact X-MMe-Client-Info value
      clientInfo = strOrNull(pick(dev, [
        "serverFriendlyDescription",
        "clientInfo",
        "compatibleDescription",
      ]));
      uuidTried = tryReadLocalUserUuid(dev);
      localUserUuid = pickBestUuid(uuidTried);
      productModel = strOrNull(pick(dev, [
        "productType",
        "modelNumber",
        "deviceModel",
      ]));
    }
  } catch (_) {}

  // Fallback Client-Info from UIDevice + sysctl-ish strings
  if (!clientInfo) {
    try {
      const UIDevice = ObjC.classes.UIDevice;
      const NSProcessInfo = ObjC.classes.NSProcessInfo;
      const u = UIDevice ? UIDevice.currentDevice() : null;
      const model = productModel
        || (u ? strOrNull(u.model()) : null)
        || "iPhone";
      let osVer = null;
      let osName = "iPhone OS";
      if (u) {
        osVer = strOrNull(u.systemVersion());
        const sn = strOrNull(u.systemName());
        if (sn) osName = sn;
      }
      let build = null;
      try {
        if (NSProcessInfo) {
          const pi = NSProcessInfo.processInfo();
          const dict = pi.operatingSystemVersionString();
          // weak; build often needs Gestalt — leave blank if unknown
          build = strOrNull(dict);
        }
      } catch (_) {}
      // Prefer AK format; if no build, still emit a usable-ish string
      if (osVer) {
        const buildPart = build && build.indexOf("(") >= 0
          ? build
          : (build || "unknown");
        clientInfo = "<" + model + "> <" + osName + ";" + osVer + ";" + buildPart
          + "> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
      }
    } catch (_) {}
  }

  let rinfo = "";
  try {
    const r = data.routingInfo();
    rinfo = String(asNumber(r) || r);
  } catch (e) {
    rinfo = "";
  }

  // Also try Client-Info / LU on AKAnisetteData itself
  if (!clientInfo) {
    clientInfo = strOrNull(pick(data, [
      "routingInfoDescription",
      "clientInfo",
      "serverFriendlyDescription",
    ]));
  }
  if (!localUserUuid) {
    const lu = pick(data, ["localUserID", "localUserId", "localUserUUID"]);
    localUserUuid = strOrNull(lu);
  }

  const luDiag = {
    selectors: listAkDeviceUserSelectors(),
    uuidTried: uuidTried,
    akRequest: null,
  };

  // 1) Preferred: AuthKit header dictionary / request helpers
  const fromReq = mdLuFromAnisetteHeadersDict(data);
  luDiag.akRequest = {
    how: fromReq.info.how,
    err: fromReq.info.err,
    akMethods: (fromReq.info.akMethods || []).filter(function (m) {
      return /LocalUser|Anisette|MD-LU|UUIDHash|anisetteHeaders/i.test(m);
    }),
    headerKeys: fromReq.info.headers ? Object.keys(fromReq.info.headers) : [],
    sample: fromReq.info.headers
      ? Object.keys(fromReq.info.headers)
          .filter(function (k) {
            return /MD-LU|MD-M|Client-Info|Device-Id|UDID/i.test(k);
          })
          .reduce(function (acc, k) {
            acc[k] = fromReq.info.headers[k];
            return acc;
          }, {})
      : null,
  };
  if (fromReq.mdLu) mdLu = fromReq.mdLu;

  // 2) Fallback: SHA-256(localUserUUID) only for a real UUID string
  if (!mdLu && isRealUuid(localUserUuid)) {
    mdLu = sha256HexUtf8(localUserUuid);
    if (!mdLu) {
      const compact = String(localUserUuid).replace(/-/g, "");
      if (compact !== localUserUuid) mdLu = sha256HexUtf8(compact);
    }
    if (mdLu) luDiag.akRequest.how = "sha256(localUserUUID)";
  }

  const midRaw = pick(data, ["machineID", "machineId", "mid"]);
  const otpRaw = pick(data, ["oneTimePassword", "otp", "oneTimePasswordData"]);

  const mid = coerceToB64(midRaw);
  const otp = coerceToB64(otpRaw);

  const out = {
    ok: true,
    frida: Frida.version,
    "X-Apple-I-MD-M": mid.b64,
    "X-Apple-I-MD": otp.b64,
    "X-Apple-I-MD-RINFO": rinfo,
    "X-Apple-I-MD-LU": mdLu,
    "X-Mme-Device-Id": deviceId,
    "X-MMe-Client-Info": clientInfo,
    localUserUUID: localUserUuid,
    _lu_diag: luDiag,
  };
  emit(out);
}

tryAnisette();
