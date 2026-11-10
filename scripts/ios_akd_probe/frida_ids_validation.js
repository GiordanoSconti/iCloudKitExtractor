/**
 * Frida: capture IDS validation-data (safe HTTP-only hooks).
 * Avoid global NSDictionary hooks — they crash identityservicesd.
 *
 * Wait for id-register / initializeValidation POSTs (gzip plist).
 */
'use strict';

var MARKER = '__IDS_VALIDATION_JSON__';
var HTTP_MARKER = '__IDS_HTTP__';
var lastB64 = null;
var seen = {};

function bytesToBase64(u8) {
  if (!u8) return '';
  if (!(u8 instanceof Uint8Array)) u8 = new Uint8Array(u8);
  var tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var out = '';
  for (var i = 0; i < u8.length; i += 3) {
    var a = u8[i], b = i + 1 < u8.length ? u8[i + 1] : 0, c = i + 2 < u8.length ? u8[i + 2] : 0;
    var n = (a << 16) | (b << 8) | c;
    out += tab[(n >> 18) & 63] + tab[(n >> 12) & 63];
    out += (i + 1 < u8.length ? tab[(n >> 6) & 63] : '=');
    out += (i + 2 < u8.length ? tab[n & 63] : '=');
  }
  return out;
}

function nsDataToU8(nsData) {
  try {
    if (!nsData || nsData.isNull()) return null;
    var len = parseInt(nsData.length(), 10);
    if (!len || len <= 0 || len > 4 * 1024 * 1024) return null;
    var buf = nsData.bytes().readByteArray(len);
    return buf ? new Uint8Array(buf) : null;
  } catch (e) {
    return null;
  }
}

function emit(source, b64, extra) {
  if (!b64 || b64.length < 24) return;
  var key = b64.slice(0, 64) + ':' + b64.length;
  if (seen[key]) return;
  seen[key] = true;
  lastB64 = b64;
  var o = {
    validation_data_b64: b64,
    length: Math.floor((b64.length * 3) / 4),
    source: source,
    ts: Date.now()
  };
  if (extra) for (var k in extra) o[k] = extra[k];
  console.log(MARKER + JSON.stringify(o));
}

function magicOf(u8) {
  if (!u8 || u8.length < 2) return '?';
  if (u8[0] === 0x1f && u8[1] === 0x8b) return 'gzip';
  if (u8.length >= 6) {
    var s = String.fromCharCode(u8[0], u8[1], u8[2], u8[3], u8[4], u8[5]);
    if (s === 'bplist') return 'bplist';
    if (u8[0] === 0x3c) return 'xml';
  }
  return 'bin';
}

function asciiHas(u8, needle) {
  var n = needle.length, limit = Math.min(u8.length, 512 * 1024);
  outer:
  for (var i = 0; i + n <= limit; i++) {
    for (var j = 0; j < n; j++) if (u8[i + j] !== needle.charCodeAt(j)) continue outer;
    return true;
  }
  return false;
}

function asciiView(u8, max) {
  max = max || 65536;
  var s = '', n = Math.min(u8.length, max);
  for (var i = 0; i < n; i++) {
    var c = u8[i];
    s += (c >= 32 && c < 127) ? String.fromCharCode(c) : (c === 9 || c === 10 || c === 13 ? String.fromCharCode(c) : '.');
  }
  return s;
}

/** Minimal inflate for gzip via Compression framework / zlib if present; else null. */
function tryGunzip(u8) {
  if (magicOf(u8) !== 'gzip') return u8;
  try {
    // Prefer NSData writing to temp + no — use CompressionStream not available.
    // On iOS, libz inflate via NativeFunction.
    var inflateInit2_ = Module.findGlobalExportByName
      ? Module.findGlobalExportByName('inflateInit2_')
      : Module.findExportByName('libz.1.dylib', 'inflateInit2_');
    var inflate = Module.findGlobalExportByName
      ? Module.findGlobalExportByName('inflate')
      : Module.findExportByName('libz.1.dylib', 'inflate');
    var inflateEnd = Module.findGlobalExportByName
      ? Module.findGlobalExportByName('inflateEnd')
      : Module.findExportByName('libz.1.dylib', 'inflateEnd');
    if (!inflateInit2_ || !inflate || !inflateEnd) return null;

    // z_stream is large; keep simple: skip gunzip in-process if fragile.
    // Instead rely on ASCII search after Apple sometimes sends xml uncompressed,
    // and on ObjC NSData decompressed copies if we see them.
    return null;
  } catch (e) {
    return null;
  }
}

function extractValidationB64FromAscii(ascii) {
  var idx = ascii.indexOf('validation-data');
  if (idx < 0) {
    idx = ascii.indexOf('validationData');
    if (idx < 0) return null;
  }
  var dataTag = ascii.indexOf('<data', idx);
  if (dataTag < 0) return null;
  var start = ascii.indexOf('>', dataTag) + 1;
  var end = ascii.indexOf('</data>', start);
  if (start <= 0 || end <= start) return null;
  var b64 = ascii.slice(start, end).replace(/\s+/g, '');
  return b64.length > 24 ? b64 : null;
}

function interestingUrl(url) {
  if (!url) return false;
  url = String(url).toLowerCase();
  return (
    url.indexOf('identity.ess') >= 0 ||
    url.indexOf('profile.ess') >= 0 ||
    url.indexOf('register') >= 0 ||
    url.indexOf('validation') >= 0 ||
    url.indexOf('idsget') >= 0 ||
    url.indexOf('authenticate') >= 0
  );
}

function looksLikeRegister(url) {
  url = String(url || '').toLowerCase();
  return (
    url.indexOf('register') >= 0 ||
    url.indexOf('initializevalidation') >= 0 ||
    url.indexOf('id-register') >= 0
  );
}

function dumpRequestIdentity(req, url, note) {
  // Push token + related IDS headers from the live iPhone request.
  try {
    if (!req || req.isNull()) return;
    var headers = req.allHTTPHeaderFields();
    if (!headers || headers.isNull()) return;
    var keys = headers.allKeys();
    var count = parseInt(keys.count(), 10);
    var interesting = {};
    for (var i = 0; i < count; i++) {
      var k = keys.objectAtIndex_(i).toString();
      var kl = k.toLowerCase();
      if (
        kl.indexOf('push') >= 0 ||
        kl.indexOf('auth-user') >= 0 ||
        kl.indexOf('protocol-version') >= 0 ||
        kl.indexOf('id-') === 0 ||
        kl === 'user-agent'
      ) {
        var v = headers.objectForKey_(keys.objectAtIndex_(i)).toString();
        interesting[k] = v.length > 240 ? v.slice(0, 240) + '…' : v;
      }
    }
    if (Object.keys(interesting).length) {
      console.log('__IDS_HEADERS__' + JSON.stringify({
        url: String(url || '').slice(0, 220),
        note: note,
        headers: interesting,
        ts: Date.now()
      }));
    }
  } catch (e) {}
}

function handleBody(url, u8, note) {
  if (!u8 || u8.length < 16) return;
  var mag = magicOf(u8);
  var isReg = looksLikeRegister(url);
  console.log(HTTP_MARKER + JSON.stringify({
    url: String(url || '').slice(0, 220),
    note: note,
    body_len: u8.length,
    magic: mag,
    registerish: isReg,
    has_validation_ascii: asciiHas(u8, 'validation-data'),
    ts: Date.now()
  }));

  // Uncompressed xml/bplist
  if (mag === 'xml' || mag === 'bplist' || mag === 'bin') {
    var ascii = asciiView(u8, Math.min(u8.length, 512 * 1024));
    var b64 = extractValidationB64FromAscii(ascii);
    if (b64) emit(note + ':ascii-extract:' + mag, b64, { url: String(url).slice(0, 120) });
  }

  // Always ship gzip bodies to Python for offline gunzip + validation-data extract.
  // (In-process zlib/Compression is fragile and previously skipped emit when
  // compression_decode_buffer was present.)
  if (mag === 'gzip' && (isReg || u8.length >= 400)) {
    console.log('__IDS_GZIP__' + JSON.stringify({
      url: String(url || '').slice(0, 220),
      note: note,
      body_len: u8.length,
      gzip_b64: bytesToBase64(u8),
      ts: Date.now()
    }));
  }
}

function safeUrl(req) {
  try {
    return req.URL().absoluteString().toString();
  } catch (e) {
    return '';
  }
}

function hookHttpSafe() {
  if (!ObjC.available) {
    console.log('[!] ObjC unavailable');
    return;
  }

  function attach(cls, sel, enter) {
    try {
      var C = ObjC.classes[cls];
      if (!C || !C[sel]) return;
      Interceptor.attach(C[sel].implementation, { onEnter: enter });
      console.log('[+] ' + cls + ' ' + sel);
    } catch (e) {
      console.log('[-] ' + cls + ' ' + sel + ': ' + e);
    }
  }

  attach('NSMutableURLRequest', '- setHTTPBody:', function (args) {
    try {
      var req = new ObjC.Object(args[0]);
      var body = new ObjC.Object(args[2]);
      var url = safeUrl(req);
      if (!interestingUrl(url)) {
        var u8q = nsDataToU8(body);
        if (u8q && asciiHas(u8q, 'validation-data')) {
          dumpRequestIdentity(req, url || '(no-url)', 'setHTTPBody-novalurl');
          handleBody(url || '(no-url)', u8q, 'setHTTPBody-novalurl');
        }
        return;
      }
      dumpRequestIdentity(req, url, 'setHTTPBody');
      var u8 = nsDataToU8(body);
      if (u8) handleBody(url, u8, 'setHTTPBody');
    } catch (e) {}
  });

  attach('NSURLSession', '- dataTaskWithRequest:', function (args) {
    try {
      var req = new ObjC.Object(args[2]);
      var url = safeUrl(req);
      if (!interestingUrl(url)) return;
      console.log('[http] dataTask ' + url);
      dumpRequestIdentity(req, url, 'dataTask');
      var body = req.HTTPBody();
      var u8 = nsDataToU8(body);
      if (u8) handleBody(url, u8, 'dataTask');
    } catch (e) {}
  });

  attach('NSURLSession', '- dataTaskWithRequest:completionHandler:', function (args) {
    try {
      var req = new ObjC.Object(args[2]);
      var url = safeUrl(req);
      if (!interestingUrl(url)) return;
      console.log('[http] dataTask+cb ' + url);
      dumpRequestIdentity(req, url, 'dataTask+cb');
      var body = req.HTTPBody();
      var u8 = nsDataToU8(body);
      if (u8) handleBody(url, u8, 'dataTask+cb');
    } catch (e) {}
  });

  attach('NSURLSession', '- uploadTaskWithRequest:fromData:', function (args) {
    try {
      var req = new ObjC.Object(args[2]);
      var url = safeUrl(req);
      var data = new ObjC.Object(args[3]);
      if (!interestingUrl(url)) return;
      console.log('[http] upload ' + url);
      dumpRequestIdentity(req, url, 'upload');
      var u8 = nsDataToU8(data);
      if (u8) handleBody(url, u8, 'upload');
    } catch (e) {}
  });
}

rpc.exports = {
  last: function () { return lastB64; },
  ping: function () { return 'ids-validation-safe'; }
};

console.log('[*] frida_ids_validation.js SAFE v3 — HTTP hooks; gzip bodies → __IDS_GZIP__');
console.log('[*] Expect idsGetHandles → initializeValidation → register (gzip with validation-data)');
hookHttpSafe();
console.log('[*] listening — sign out/in iMessage while attached');
