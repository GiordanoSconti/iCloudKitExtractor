/**
 * Frida: dump APSClientIdentity (push cert + RSA private key) from apsd.
 *
 *   frida -H PHONE:27042 -n apsd -l frida_aps_push_identity.js
 *
 * Emits:
 *   __APS_PUSH_JSON__{ "cert_pem": "...", "key_pem": "...", ... }
 */
'use strict';

var MARKER = '__APS_PUSH_JSON__';

function resolveExport(modName, sym) {
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      var g = Module.findGlobalExportByName(sym);
      if (g) return g;
    }
  } catch (e) {}
  try {
    if (typeof Module.findExportByName === 'function') {
      var e1 = Module.findExportByName(modName, sym);
      if (e1) return e1;
      var e2 = Module.findExportByName(null, sym);
      if (e2) return e2;
    }
  } catch (e) {}
  try {
    var m = Process.getModuleByName(modName);
    if (m && typeof m.findExportByName === 'function') {
      var e3 = m.findExportByName(sym);
      if (e3) return e3;
    }
    if (m && typeof m.getExportByName === 'function') {
      var e4 = m.getExportByName(sym);
      if (e4) return e4;
    }
  } catch (e) {}
  return null;
}

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
    if (!len || len <= 0 || len > 16 * 1024) return null;
    var buf = nsData.bytes().readByteArray(len);
    return buf ? new Uint8Array(buf) : null;
  } catch (e) {
    return null;
  }
}

function derToPem(kind, u8) {
  var b64 = bytesToBase64(u8);
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return '-----BEGIN ' + kind + '-----\n' + lines.join('\n') + '\n-----END ' + kind + '-----\n';
}

function boolYes() {
  return ObjC.classes.NSNumber.numberWithBool_(true);
}

function buildQuery(klass, extras) {
  var d = ObjC.classes.NSMutableDictionary.alloc().init();
  // Frida auto-bridges JS strings → NSString for ObjC selectors.
  d.setObject_forKey_(klass, 'class');
  d.setObject_forKey_('APSClientIdentity', 'labl');
  d.setObject_forKey_('m_LimitOne', 'm_Limit');
  if (extras) {
    for (var k in extras) {
      if (Object.prototype.hasOwnProperty.call(extras, k))
        d.setObject_forKey_(extras[k], k);
    }
  }
  return d;
}

function secItemCopyMatching(queryDict) {
  var addr = resolveExport('Security', 'SecItemCopyMatching');
  if (!addr)
    throw new Error('SecItemCopyMatching export not found');
  var fn = new NativeFunction(addr, 'int', ['pointer', 'pointer']);
  var outPtr = Memory.alloc(Process.pointerSize);
  outPtr.writePointer(ptr(0));
  var st = fn(queryDict.handle, outPtr);
  var p = outPtr.readPointer();
  return { status: st, ref: p.isNull() ? null : new ObjC.Object(p) };
}

function tryExportSecKey(secKey) {
  if (!secKey || secKey.isNull()) return null;
  var addr = resolveExport('Security', 'SecKeyCopyExternalRepresentation');
  if (!addr) return null;
  var fn = new NativeFunction(addr, 'pointer', ['pointer', 'pointer']);
  var errPtr = Memory.alloc(Process.pointerSize);
  errPtr.writePointer(ptr(0));
  var dataPtr = fn(secKey.handle, errPtr);
  if (dataPtr.isNull()) return null;
  return nsDataToU8(new ObjC.Object(dataPtr));
}

function nativeInt2(name) {
  var addr = resolveExport('Security', name);
  if (!addr) throw new Error(name + ' export not found');
  return new NativeFunction(addr, 'int', ['pointer', 'pointer']);
}

function nativePtr1(name) {
  var addr = resolveExport('Security', name);
  if (!addr) throw new Error(name + ' export not found');
  return new NativeFunction(addr, 'pointer', ['pointer']);
}

function dumpOnce() {
  if (!ObjC.available) {
    console.log('[!] ObjC unavailable');
    return false;
  }

  var certPem = null;
  var keyPem = null;
  var notes = [];

  var secItemAddr = resolveExport('Security', 'SecItemCopyMatching');
  notes.push('SecItemCopyMatching=' + (secItemAddr ? secItemAddr : 'null'));

  // 1) Certificate data
  try {
    var qCert = buildQuery('cert', {
      r_Data: boolYes(),
      agrp: 'com.apple.apsd'
    });
    var r1 = secItemCopyMatching(qCert);
    notes.push('cert+agrp status=' + r1.status);
    if (r1.status === 0 && r1.ref) {
      var cBytes = nsDataToU8(r1.ref);
      if (cBytes && cBytes.length > 64) certPem = derToPem('CERTIFICATE', cBytes);
    }
  } catch (e) {
    notes.push('cert+agrp err=' + e);
  }

  if (!certPem) {
    try {
      var qCert2 = buildQuery('cert', { r_Data: boolYes() });
      var r1b = secItemCopyMatching(qCert2);
      notes.push('cert status=' + r1b.status);
      if (r1b.status === 0 && r1b.ref) {
        var cBytes2 = nsDataToU8(r1b.ref);
        if (cBytes2 && cBytes2.length > 64) certPem = derToPem('CERTIFICATE', cBytes2);
      }
    } catch (e) {
      notes.push('cert err=' + e);
    }
  }

  // 2) Private key as data
  try {
    var qKey = buildQuery('keys', {
      r_Data: boolYes(),
      agrp: 'com.apple.apsd'
    });
    var r2 = secItemCopyMatching(qKey);
    notes.push('keys+agrp+r_Data status=' + r2.status);
    if (r2.status === 0 && r2.ref) {
      var kBytes = nsDataToU8(r2.ref);
      if (kBytes && kBytes.length > 64) keyPem = derToPem('RSA PRIVATE KEY', kBytes);
    }
  } catch (e) {
    notes.push('keys data err=' + e);
  }

  if (!keyPem) {
    try {
      var qKey2 = buildQuery('keys', { r_Data: boolYes() });
      var r2b = secItemCopyMatching(qKey2);
      notes.push('keys+r_Data status=' + r2b.status);
      if (r2b.status === 0 && r2b.ref) {
        var kBytes2 = nsDataToU8(r2b.ref);
        if (kBytes2 && kBytes2.length > 64) keyPem = derToPem('RSA PRIVATE KEY', kBytes2);
      }
    } catch (e) {
      notes.push('keys data2 err=' + e);
    }
  }

  // 3) Identity ref → private key + cert
  if (!keyPem || !certPem) {
    try {
      var qId = buildQuery('idnt', {
        r_Ref: boolYes(),
        agrp: 'com.apple.apsd'
      });
      var r3 = secItemCopyMatching(qId);
      notes.push('idnt+agrp status=' + r3.status);
      if (r3.status !== 0 || !r3.ref) {
        qId = buildQuery('idnt', { r_Ref: boolYes() });
        r3 = secItemCopyMatching(qId);
        notes.push('idnt status=' + r3.status);
      }
      if (r3.status === 0 && r3.ref) {
        if (!keyPem) {
          var SecIdentityCopyPrivateKey = nativeInt2('SecIdentityCopyPrivateKey');
          var keyOut = Memory.alloc(Process.pointerSize);
          keyOut.writePointer(ptr(0));
          var stK = SecIdentityCopyPrivateKey(r3.ref.handle, keyOut);
          notes.push('CopyPrivateKey status=' + stK);
          var keyRef = keyOut.readPointer();
          if (stK === 0 && !keyRef.isNull()) {
            var exported = tryExportSecKey(new ObjC.Object(keyRef));
            if (exported && exported.length > 64) {
              keyPem = derToPem('RSA PRIVATE KEY', exported);
            } else {
              notes.push('SecKeyCopyExternalRepresentation failed (non-exportable?)');
            }
          }
        }
        if (!certPem) {
          var SecIdentityCopyCertificate = nativeInt2('SecIdentityCopyCertificate');
          var certOut = Memory.alloc(Process.pointerSize);
          certOut.writePointer(ptr(0));
          var stC = SecIdentityCopyCertificate(r3.ref.handle, certOut);
          notes.push('CopyCertificate status=' + stC);
          var certRef = certOut.readPointer();
          if (stC === 0 && !certRef.isNull()) {
            var SecCertificateCopyData = nativePtr1('SecCertificateCopyData');
            var cd = SecCertificateCopyData(certRef);
            if (!cd.isNull()) {
              var cBytes3 = nsDataToU8(new ObjC.Object(cd));
              if (cBytes3 && cBytes3.length > 64)
                certPem = derToPem('CERTIFICATE', cBytes3);
            }
          }
        }
      }
    } catch (e) {
      notes.push('idnt err=' + e);
    }
  }

  // 4) Broad scan: any item labeled APSClientIdentity
  if (!certPem || !keyPem) {
    try {
      var qAll = ObjC.classes.NSMutableDictionary.alloc().init();
      qAll.setObject_forKey_('APSClientIdentity', 'labl');
      qAll.setObject_forKey_(boolYes(), 'r_Attributes');
      qAll.setObject_forKey_('m_LimitAll', 'm_Limit');
      var rAll = secItemCopyMatching(qAll);
      notes.push('scan-labl status=' + rAll.status + ' type=' + (rAll.ref ? rAll.ref.$className : 'null'));
    } catch (e) {
      notes.push('scan err=' + e);
    }
  }

  var ok = !!(certPem && keyPem);
  var payload = {
    ok: ok,
    cert_pem: certPem,
    key_pem: keyPem,
    cert_len: certPem ? certPem.length : 0,
    key_len: keyPem ? keyPem.length : 0,
    notes: notes,
    ts: Date.now()
  };
  console.log(MARKER + JSON.stringify(payload));
  if (ok) console.log('[+] APSClientIdentity dumped (cert+key PEM)');
  else console.log('[-] incomplete dump — ' + notes.join('; '));
  return ok;
}

rpc.exports = {
  dump: function () { return dumpOnce(); },
  ping: function () { return 'aps-push-identity-v2'; }
};

console.log('[*] frida_aps_push_identity.js v2 — resolveExport + APSClientIdentity dump');
setTimeout(function () { dumpOnce(); }, 400);
