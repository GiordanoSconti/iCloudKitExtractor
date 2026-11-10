/**
 * Frida: dump ALL identityservicesd IDS HTTP (request + response).
 * Safer than global NSDictionary hooks — NSURLSession / NSMutableURLRequest only.
 *
 * Markers for Python:
 *   __IDS_REQ__  full request (url, method, headers, body_b64, magic)
 *   __IDS_RESP__ response (url, status, headers, body_b64, magic)
 *   __IDS_HTTP__ short one-liner (compat)
 */
'use strict';

var REQ_MARKER = '__IDS_REQ__';
var RESP_MARKER = '__IDS_RESP__';
var HTTP_MARKER = '__IDS_HTTP__';
var seq = 0;
var seenBody = {};

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
    if (!len || len <= 0 || len > 8 * 1024 * 1024) return null;
    var buf = nsData.bytes().readByteArray(len);
    return buf ? new Uint8Array(buf) : null;
  } catch (e) {
    return null;
  }
}

function magicOf(u8) {
  if (!u8 || u8.length < 2) return 'empty';
  if (u8[0] === 0x1f && u8[1] === 0x8b) return 'gzip';
  if (u8.length >= 6) {
    var s = String.fromCharCode(u8[0], u8[1], u8[2], u8[3], u8[4], u8[5]);
    if (s === 'bplist') return 'bplist';
  }
  if (u8[0] === 0x3c || u8[0] === 0x7b) return 'text';
  return 'bin';
}

function interestingUrl(url) {
  if (!url) return false;
  url = String(url).toLowerCase();
  return (
    url.indexOf('identity.ess') >= 0 ||
    url.indexOf('profile.ess') >= 0 ||
    url.indexOf('id-') >= 0 ||
    url.indexOf('ids-') >= 0 ||
    url.indexOf('register') >= 0 ||
    url.indexOf('validation') >= 0 ||
    url.indexOf('authenticate') >= 0 ||
    url.indexOf('query') >= 0 ||
    url.indexOf('lookup') >= 0 ||
    url.indexOf('apple.com') >= 0 && (
      url.indexOf('ess') >= 0 ||
      url.indexOf('ids') >= 0 ||
      url.indexOf('albert') >= 0 ||
      url.indexOf('gsa') >= 0
    )
  );
}

function headerDict(nsDict) {
  var out = {};
  try {
    if (!nsDict || nsDict.isNull()) return out;
    var keys = nsDict.allKeys();
    var count = parseInt(keys.count(), 10);
    for (var i = 0; i < count; i++) {
      var k = keys.objectAtIndex_(i).toString();
      var v = nsDict.objectForKey_(keys.objectAtIndex_(i)).toString();
      out[k] = v.length > 4000 ? v.slice(0, 4000) + '…' : v;
    }
  } catch (e) {}
  return out;
}

function safeUrl(req) {
  try {
    return req.URL().absoluteString().toString();
  } catch (e) {
    return '';
  }
}

function safeMethod(req) {
  try {
    return req.HTTPMethod().toString();
  } catch (e) {
    return '?';
  }
}

function emitReq(url, method, headers, u8, note) {
  seq += 1;
  var id = seq;
  var bodyB64 = u8 ? bytesToBase64(u8) : '';
  var dedupe = (url || '') + ':' + (u8 ? u8.length : 0) + ':' + bodyB64.slice(0, 48);
  if (seenBody[dedupe]) return id;
  seenBody[dedupe] = true;

  var payload = {
    id: id,
    dir: 'req',
    note: note,
    method: method || '?',
    url: String(url || ''),
    headers: headers || {},
    body_len: u8 ? u8.length : 0,
    magic: magicOf(u8),
    body_b64: bodyB64,
    ts: Date.now()
  };
  console.log(REQ_MARKER + JSON.stringify(payload));
  console.log(HTTP_MARKER + JSON.stringify({
    id: id,
    dir: 'req',
    method: payload.method,
    url: payload.url.slice(0, 240),
    body_len: payload.body_len,
    magic: payload.magic,
    note: note,
    ts: payload.ts
  }));
  return id;
}

function emitResp(url, status, headers, u8, note, reqId) {
  seq += 1;
  var id = seq;
  var payload = {
    id: id,
    req_id: reqId || null,
    dir: 'resp',
    note: note,
    status: status,
    url: String(url || ''),
    headers: headers || {},
    body_len: u8 ? u8.length : 0,
    magic: magicOf(u8),
    body_b64: u8 ? bytesToBase64(u8) : '',
    ts: Date.now()
  };
  console.log(RESP_MARKER + JSON.stringify(payload));
  console.log(HTTP_MARKER + JSON.stringify({
    id: id,
    req_id: reqId || null,
    dir: 'resp',
    status: status,
    url: payload.url.slice(0, 240),
    body_len: payload.body_len,
    magic: payload.magic,
    note: note,
    ts: payload.ts
  }));
  return id;
}

function dumpRequest(req, note, overrideBody) {
  try {
    if (!req || req.isNull()) return null;
    var url = safeUrl(req);
    if (!interestingUrl(url)) return null;
    var method = safeMethod(req);
    var headers = headerDict(req.allHTTPHeaderFields());
    var u8 = overrideBody || nsDataToU8(req.HTTPBody());
    return emitReq(url, method, headers, u8, note);
  } catch (e) {
    console.log('[-] dumpRequest: ' + e);
    return null;
  }
}

function hookHttp() {
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
      if (!interestingUrl(url) && !nsDataLooksIds(body)) return;
      dumpRequest(req, 'setHTTPBody', nsDataToU8(body));
    } catch (e) {}
  });

  attach('NSURLSession', '- dataTaskWithRequest:', function (args) {
    try {
      dumpRequest(new ObjC.Object(args[2]), 'dataTask');
    } catch (e) {}
  });

  attach('NSURLSession', '- dataTaskWithRequest:completionHandler:', function (args) {
    try {
      var req = new ObjC.Object(args[2]);
      var reqId = dumpRequest(req, 'dataTask+cb');
      if (reqId == null) return;
      // Wrap completion to capture response body when possible.
      try {
        var orig = new ObjC.Block(args[3]);
        var url = safeUrl(req);
        var Block = ObjC.implement(orig, function (data, response, error) {
          try {
            var status = 0;
            var hdrs = {};
            var respUrl = url;
            if (response && !response.isNull()) {
              var r = new ObjC.Object(response);
              try { status = parseInt(r.statusCode(), 10); } catch (e1) {}
              try {
                if (r.allHeaderFields) hdrs = headerDict(r.allHeaderFields());
              } catch (e2) {}
              try {
                if (r.URL) respUrl = r.URL().absoluteString().toString();
              } catch (e3) {}
            }
            var u8 = nsDataToU8(data);
            emitResp(respUrl, status, hdrs, u8, 'completion', reqId);
            if (error && !error.isNull()) {
              console.log('[http] error req#' + reqId + ' ' + new ObjC.Object(error).toString());
            }
          } catch (e) {
            console.log('[-] completion wrap: ' + e);
          }
          return orig.implementation(data, response, error);
        });
        args[3] = Block;
      } catch (e) {
        // Block wrap can fail on some iOS / Frida combos — request dump still useful.
      }
    } catch (e) {}
  });

  attach('NSURLSession', '- uploadTaskWithRequest:fromData:', function (args) {
    try {
      var req = new ObjC.Object(args[2]);
      var data = new ObjC.Object(args[3]);
      dumpRequest(req, 'upload', nsDataToU8(data));
    } catch (e) {}
  });

  // CFNetwork-ish fallback: NSURLConnection (older paths)
  attach('NSURLConnection', '+ sendSynchronousRequest:returningResponse:error:', function (args) {
    try {
      dumpRequest(new ObjC.Object(args[2]), 'NSURLConnection.sync');
    } catch (e) {}
  });
}

function nsDataLooksIds(nsData) {
  try {
    var u8 = nsDataToU8(nsData);
    if (!u8 || u8.length < 16) return false;
    // crude: look for validation-data / madrid / identity.ess ascii
    var n = Math.min(u8.length, 64 * 1024);
    var hits = ['validation-data', 'com.apple.madrid', 'identity.ess', 'profile.ess'];
    for (var h = 0; h < hits.length; h++) {
      var needle = hits[h];
      outer:
      for (var i = 0; i + needle.length <= n; i++) {
        for (var j = 0; j < needle.length; j++) {
          if (u8[i + j] !== needle.charCodeAt(j)) continue outer;
        }
        return true;
      }
    }
  } catch (e) {}
  return false;
}

rpc.exports = {
  ping: function () { return 'ids-http-capture-v1'; },
  seq: function () { return seq; }
};

console.log('[*] frida_ids_http_capture.js v1 — full IDS req/resp dump');
hookHttp();
console.log('[*] listening on identityservicesd — toggle iMessage / FaceTime / lookup');
