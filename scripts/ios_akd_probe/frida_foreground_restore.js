// Recover Foreground Restore MMCS identity (hardware-id + plist-sha256).
//
//   python fetch_foreground_restore.py -H IP:27042
//   python -m frida_tools.repl -H IP:27042 -n backupd -l frida_foreground_restore.js
//
// Targets: backupd (preferred), cloudd, akd. Values often appear only when a
// Prepare Restore / MMCS authorize path runs — use --wait and trigger Settings
// → iCloud → Manage Storage → Backups → Download (or start IKE Prepare Restore).

var MARKER = "__FG_RESTORE_JSON__";
var KNOWN_HW = "69A01E7605308B82DC2D16C2EE5708EBF809D270A77C4C001C080FB95E10A7FA";
var KNOWN_SHA = "T4puFGiGd8+Ps3UvjxZcJvUpp8qKADTniDwLwlDqaD0=";

var state = {
  hardwareIdHex: null,
  plistSha256Base64: null,
  plistVersion: null,
  protoVersion: null,
  mmeClientInfo: null,
  sources: [],
  hits: [],
  hooks: [],
  modules: [],
};

function emit(payload) {
  try { send(payload); } catch (_) {}
  console.log(MARKER + JSON.stringify(payload));
}

function note(source, extra) {
  var row = Object.assign({ source: source, t: Date.now() }, extra || {});
  state.hits.push(row);
  if (state.hits.length > 40) state.hits.shift();
  console.log("[fg] " + source + " " + JSON.stringify(extra || {}));
}

function setHw(hex, source) {
  if (!hex || typeof hex !== "string") return false;
  var h = hex.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
  if (h.length !== 64) return false;
  if (state.hardwareIdHex === h) return true;
  state.hardwareIdHex = h;
  if (state.sources.indexOf(source) < 0) state.sources.push(source);
  note(source, { hardwareIdHex: h });
  maybeDone();
  return true;
}

function setSha(b64, source) {
  if (!b64 || typeof b64 !== "string") return false;
  var s = b64.trim();
  if (!/^[A-Za-z0-9+/]{43}=$/.test(s)) return false;
  if (state.plistSha256Base64 === s) return true;
  state.plistSha256Base64 = s;
  if (state.sources.indexOf(source) < 0) state.sources.push(source);
  note(source, { plistSha256Base64: s });
  maybeDone();
  return true;
}

function setMeta(key, val, source) {
  if (!val) return;
  if (state[key] !== val) {
    state[key] = val;
    note(source, { [key]: val });
  }
}

function maybeDone() {
  if (state.hardwareIdHex && state.plistSha256Base64) {
    emit(buildResult(true, "both_values"));
  }
}

function buildResult(ok, reason) {
  return {
    ok: !!ok,
    reason: reason || null,
    process: Process.id,
    processName: tryProcessName(),
    hardwareIdHex: state.hardwareIdHex,
    plistSha256Base64: state.plistSha256Base64,
    plistVersion: state.plistVersion,
    protoVersion: state.protoVersion,
    mmeClientInfo: state.mmeClientInfo,
    matchesKnown:
      state.hardwareIdHex === KNOWN_HW &&
      state.plistSha256Base64 === KNOWN_SHA,
    sources: state.sources.slice(),
    hooks: state.hooks.slice(),
    modules: state.modules.slice(0, 30),
    recentHits: state.hits.slice(-12),
    frida: typeof Frida !== "undefined" ? Frida.version : null,
  };
}

function tryProcessName() {
  try {
    return Process.enumerateModules()[0].name;
  } catch (_) {
    return null;
  }
}

function asciiFromPtr(p, maxLen) {
  try {
    if (!p || p.isNull()) return "";
    return p.readCString(maxLen || 4096) || "";
  } catch (_) {
    return "";
  }
}

function latin1FromBytes(arr) {
  var s = "";
  for (var i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i] & 0xff);
  return s;
}

function scanText(text, source) {
  if (!text || text.length < 40) return;

  var shaIdx = text.indexOf("x-apple-mmcs-plist-sha256");
  if (shaIdx >= 0) {
    var win = text.slice(shaIdx, Math.min(text.length, shaIdx + 120));
    var mSha = win.match(/x-apple-mmcs-plist-sha256[\x00-\x20]{0,12}([A-Za-z0-9+/]{43}=)/);
    if (mSha) setSha(mSha[1], source + ":plist-sha256");
  }

  var pv = text.match(/x-apple-mmcs-proto-version[\x00-\x20]{0,12}([0-9]+\.[0-9]+)/);
  if (pv) setMeta("protoVersion", pv[1], source);
  var plv = text.match(/x-apple-mmcs-plist-version[\x00-\x20]{0,12}(v[0-9.]+)/);
  if (plv) setMeta("plistVersion", plv[1], source);
  var ci = text.match(/x-mme-client-info[\x00-\x20]{0,12}(<[^>]{8,220}>)/);
  if (ci) setMeta("mmeClientInfo", ci[1], source);

  if (text.indexOf("Foreground Restore") >= 0 || shaIdx >= 0) {
    var markers = ["x-apple-mmcs-plist-sha256", "x-apple-mmcs-proto-version", "Foreground Restore"];
    for (var mi = 0; mi < markers.length; mi++) {
      var idx = text.indexOf(markers[mi]);
      if (idx < 0) continue;
      var window = text.slice(Math.max(0, idx - 220), Math.min(text.length, idx + 220));
      var mHw = window.match(/\b([0-9A-Fa-f]{64})\b/);
      if (mHw) setHw(mHw[1], source + ":hw-near-" + markers[mi]);
    }
  }

  // Loose: any 64-hex near MMCS keywords in small buffers
  if (text.indexOf("mmcs") >= 0 || text.indexOf("MMCS") >= 0) {
    var allHw = text.match(/\b([0-9A-Fa-f]{64})\b/g);
    if (allHw && allHw.length === 1) setHw(allHw[0], source + ":lone-64hex");
  }
}

function scanRange(base, size, source) {
  try {
    var chunk = base.readByteArray(Math.min(size, 256 * 1024));
    if (!chunk) return;
    scanText(latin1FromBytes(new Uint8Array(chunk)), source);
  } catch (_) {}
}

function enumerateInterestingModules() {
  var want = [
    "backupd",
    "MobileBackup",
    "CloudKit",
    "CloudKitDaemon",
    "MMCS",
    "AuthKit",
    "AppleAccount",
    "icloud",
  ];
  Process.enumerateModules().forEach(function (m) {
    var n = m.name || "";
    for (var i = 0; i < want.length; i++) {
      if (n.indexOf(want[i]) >= 0) {
        state.modules.push(n + "@" + m.base);
        break;
      }
    }
  });
}

function scanModuleStrings() {
  Process.enumerateModules().forEach(function (m) {
    var n = (m.name || "").toLowerCase();
    if (
      n.indexOf("mobilebackup") < 0 &&
      n.indexOf("mmcs") < 0 &&
      n.indexOf("cloudkit") < 0 &&
      n.indexOf("backup") < 0 &&
      n !== "backupd"
    )
      return;
    try {
      // Heuristic: scan first 2 MiB of module for ASCII markers
      scanRange(m.base, Math.min(m.size, 2 * 1024 * 1024), "mod:" + m.name);
    } catch (_) {}
  });
}

function readFileUtf8(path) {
  try {
    if (!ObjC.available) return null;
    var ns = ObjC.classes.NSString.stringWithContentsOfFile_encoding_error_(
      path,
      4,
      ptr(0)
    );
    if (!ns || ns.isNull()) return null;
    return ns.toString();
  } catch (_) {
    return null;
  }
}

function scanKnownPaths() {
  if (!ObjC.available) return;
  var paths = [
    "/var/mobile/Library/Preferences/com.apple.mobile.ldbackup.plist",
    "/var/mobile/Library/Preferences/com.apple.MobileBackup.plist",
    "/var/mobile/Library/Preferences/com.apple.backupd.plist",
    "/var/root/Library/Preferences/com.apple.MobileBackup.plist",
    "/var/root/Library/Preferences/com.apple.backupd.plist",
    "/System/Library/PrivateFrameworks/MobileBackup.framework/Info.plist",
  ];
  for (var i = 0; i < paths.length; i++) {
    var t = readFileUtf8(paths[i]);
    if (t) scanText(t, "file:" + paths[i]);
  }
}

function hookHttpHeaders() {
  if (!ObjC.available) return;

  function grabFromDict(dict, source) {
    try {
      if (!dict || dict.isNull()) return;
      var keys = dict.allKeys();
      var n = Number(keys.count());
      for (var i = 0; i < n; i++) {
        var k = keys.objectAtIndex_(i).toString();
        var v = dict.objectForKey_(keys.objectAtIndex_(i));
        var vs = v ? v.toString() : "";
        var kl = k.toLowerCase();
        if (kl.indexOf("mmcs-plist-sha256") >= 0) setSha(vs, source + ":" + k);
        if (kl.indexOf("mmcs-plist-version") >= 0) setMeta("plistVersion", vs, source);
        if (kl.indexOf("mmcs-proto-version") >= 0) setMeta("protoVersion", vs, source);
        if (kl.indexOf("mme-client-info") >= 0) setMeta("mmeClientInfo", vs, source);
        if (/^[0-9A-Fa-f]{64}$/.test(vs)) setHw(vs, source + ":hdr-value");
      }
    } catch (e) {
      note("hook-err", { err: String(e) });
    }
  }

  try {
    var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    if (NSMutableURLRequest) {
      Interceptor.attach(NSMutableURLRequest["- setValue:forHTTPHeaderField:"].implementation, {
        onEnter: function (args) {
          try {
            var val = new ObjC.Object(args[2]).toString();
            var key = new ObjC.Object(args[3]).toString();
            var kl = key.toLowerCase();
            if (kl.indexOf("mmcs-plist-sha256") >= 0) setSha(val, "NSURLRequest:" + key);
            if (kl.indexOf("mmcs-plist-version") >= 0) setMeta("plistVersion", val, "NSURLRequest");
            if (kl.indexOf("mmcs-proto-version") >= 0) setMeta("protoVersion", val, "NSURLRequest");
            if (kl.indexOf("mme-client-info") >= 0) setMeta("mmeClientInfo", val, "NSURLRequest");
            if (/^[0-9A-Fa-f]{64}$/.test(val)) setHw(val, "NSURLRequest:64hex");
            if (
              kl.indexOf("mmcs") >= 0 ||
              String(val).indexOf("Foreground") >= 0
            ) {
              scanText(key + "=" + val, "NSURLRequest-pair");
            }
          } catch (_) {}
        },
      });
      state.hooks.push("NSMutableURLRequest.setValue:forHTTPHeaderField:");
    }
  } catch (e) {
    note("hook-NSURLRequest", { err: String(e) });
  }

  try {
    var NSURLRequest = ObjC.classes.NSURLRequest;
    if (NSURLRequest && NSURLRequest["- allHTTPHeaderFields"]) {
      // Observe when requests are copied / used via CFNetwork by wrapping session tasks is heavy;
      // instead intercept -[NSURLSession dataTaskWithRequest:completionHandler:]
      var NSURLSession = ObjC.classes.NSURLSession;
      if (NSURLSession && NSURLSession["- dataTaskWithRequest:completionHandler:"]) {
        Interceptor.attach(
          NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation,
          {
            onEnter: function (args) {
              try {
                var req = new ObjC.Object(args[2]);
                var headers = req.allHTTPHeaderFields();
                grabFromDict(headers, "NSURLSession.dataTask");
                var url = req.URL();
                if (url) {
                  var us = url.absoluteString().toString();
                  if (
                    us.indexOf("authorizeGet") >= 0 ||
                    us.indexOf("ckdatabase") >= 0 ||
                    us.indexOf("content") >= 0 ||
                    us.indexOf("mbksync") >= 0
                  )
                    note("url", { url: us.slice(0, 160) });
                }
                var body = req.HTTPBody();
                if (body && !body.isNull()) {
                  var len = Math.min(Number(body.length()), 8192);
                  if (len > 0) {
                    var bytes = ptr(body.bytes()).readByteArray(len);
                    if (bytes) scanText(latin1FromBytes(new Uint8Array(bytes)), "HTTPBody");
                  }
                }
              } catch (_) {}
            },
          }
        );
        state.hooks.push("NSURLSession.dataTaskWithRequest:");
      }
    }
  } catch (e) {
    note("hook-NSURLSession", { err: String(e) });
  }
}

function hookCFNetworkWrite() {
  // Catch raw socket/CFHTTP message bodies carrying Foreground Restore protobuf ASCII.
  var candidates = [
    "CFHTTPMessageSetHeaderFieldValue",
    "CFHTTPMessageSetBody",
  ];
  candidates.forEach(function (sym) {
    try {
      var p = Module.findGlobalExportByName
        ? Module.findGlobalExportByName(sym)
        : Module.getGlobalExportByName(sym);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function (args) {
          try {
            if (sym === "CFHTTPMessageSetHeaderFieldValue") {
              var k = asciiFromPtr(args[1], 128);
              var v = asciiFromPtr(args[2], 256);
              scanText(k + "\0" + v, "CFHTTP:" + k);
            } else if (sym === "CFHTTPMessageSetBody") {
              // args[1] = CFDataRef — skip if not easily readable
            }
          } catch (_) {}
        },
      });
      state.hooks.push(sym);
    } catch (_) {}
  });
}

function installMemoryScanner() {
  // Periodic light scan of anonymous RW ranges for markers (backupd often keeps copies).
  var rounds = 0;
  var timer = setInterval(function () {
    rounds++;
    if (rounds > 30) {
      clearInterval(timer);
      return;
    }
    if (state.hardwareIdHex && state.plistSha256Base64) {
      clearInterval(timer);
      return;
    }
    try {
      Process.enumerateRanges("r--").some(function (r) {
        if (r.size < 64 || r.size > 4 * 1024 * 1024) return false;
        try {
          var head = r.base.readByteArray(Math.min(r.size, 64 * 1024));
          if (!head) return false;
          var t = latin1FromBytes(new Uint8Array(head));
          if (
            t.indexOf("x-apple-mmcs-plist-sha256") >= 0 ||
            t.indexOf("Foreground Restore") >= 0
          ) {
            scanText(t, "mem-scan");
            if (r.size <= 512 * 1024) scanRange(r.base, r.size, "mem-full");
            return !!(state.hardwareIdHex && state.plistSha256Base64);
          }
        } catch (_) {}
        return false;
      });
    } catch (_) {}
  }, 2000);
}

function main() {
  enumerateInterestingModules();
  scanModuleStrings();
  scanKnownPaths();
  hookHttpHeaders();
  hookCFNetworkWrite();
  installMemoryScanner();

  emit(buildResult(
    !!(state.hardwareIdHex && state.plistSha256Base64),
    state.hardwareIdHex || state.plistSha256Base64
      ? "partial"
      : "waiting — trigger Prepare Restore / iCloud backup download, or wait for MMCS traffic"
  ));

  // Keep process alive for --wait: emit heartbeat so Python knows script is loaded
  setInterval(function () {
    if (state.hardwareIdHex && state.plistSha256Base64) return;
    emit({
      ok: false,
      heartbeat: true,
      reason: "waiting_for_mmcs_or_restore",
      hardwareIdHex: state.hardwareIdHex,
      plistSha256Base64: state.plistSha256Base64,
      hooks: state.hooks.length,
    });
  }, 8000);
}

try {
  main();
} catch (e) {
  emit({ ok: false, error: String(e), stack: e.stack || null });
}
