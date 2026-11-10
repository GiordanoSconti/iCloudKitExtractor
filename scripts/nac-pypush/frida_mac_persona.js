/**
 * Frida (macOS): dump IOKit fields used by NAC / pypush data.plist.
 *
 * Usage (on Mac):
 *   frida -n identityservicesd -l frida_mac_persona.js
 *   # or attach to any process that can call IOKit; often run against a helper:
 *   frida -f /usr/bin/true -l frida_mac_persona.js --no-pause
 *
 * Prefer capture_mac_persona.py (ioreg) when possible — same values, simpler.
 * For encrypted gibberish keys (Gq3489ugfi …) use nacserver's build_extractor on the Mac.
 *
 * Copy the printed JSON / rebuild as data.plist, then Windows → Load Mac persona.
 */
'use strict';

const GUID = '4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14';

function tryIoreg() {
  // Frida on macOS can shell out:
  const ioreg = new Module.findExportByName(null, 'system');
  console.log('[*] Prefer: python3 capture_mac_persona.py -o data.plist');
  console.log('[*] Keys needed in data.plist.iokit:');
  console.log('    IOPlatformSerialNumber (string)');
  console.log('    IOPlatformUUID (string)');
  console.log('    ' + GUID + ':MLB (data)');
  console.log('    ' + GUID + ':ROM (data)');
  console.log('    board-id, product-name, IOMACAddress (data)');
  console.log('    + encrypted keys if available from nacserver extractor');
  console.log('[*] root_disk_uuid at top level');
}

tryIoreg();
