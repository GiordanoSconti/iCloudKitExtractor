# Capture iPhone IDS `validation-data` + APS push identity (Frida)

Madrid `id-register` needs Apple `validation-data`. Without a Mac `data.plist`, Frida on
a jailbroken iPhone is an **experiment** — and it only works if the capture matches the
Windows session.

## Hard requirements (or you get 6009)

1. **Same Apple ID** on the phone iMessage account and in iCloudKitExtractor  
   (the last capture was `mailto:giordano.sconti.ios@icloud.com` while Windows enrolled
   `giordano.sconti.betatester@gmail.com` — that alone yields 6009).
2. The register body must include **`com.apple.madrid`**. FaceTime / alloy-only registers
   also carry `validation-data` but Apple rejects them for Madrid.
3. **`x-push-sig`** must use the phone’s APSClientIdentity (`fetch_aps_push_identity.py`).

If any of these fail, use a **real Mac `data.plist`** + Load Mac persona instead.

## Steps

```powershell
cd C:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudKitExtractor\scripts\ios_akd_probe

# once
python fetch_aps_push_identity.py -H PHONE_IP:27042

# wait for a Madrid register (script ignores non-Madrid validation-data)
python fetch_ids_validation.py -H PHONE_IP:27042 --timeout 300
```

While attached: Settings → Messages → sign **out** of iMessage, wait, sign **in** again
(toggle alone often only re-registers FaceTime/alloy).

Success lines:

- `[+] Madrid register uris=[mailto:…]`
- writes `validation-data.b64` + `iphone-ids-identity.json` with `"has_madrid": true`

Then Enroll Madrid (Debug) within 1–2 minutes. Log must show:

- `APS sig=iPhone-APS`
- `madrid=yes` and the **same** mailto as Windows handles

## Manual Frida

```text
frida -H PHONE_IP:27042 -n apsd -l frida_aps_push_identity.js
frida -H PHONE_IP:27042 -n identityservicesd -l frida_ids_validation.js
```

## Full IDS HTTP capture (all requests/responses)

One-shot `validation-data` dump is not the same as Mac NAC. To see what the
phone actually sends (register, initializeValidation, query, auth):

```powershell
python fetch_ids_http_capture.py -H PHONE_IP:27042 --timeout 600
```

Writes under `%AppData%/iCloudKitExtractor/madrid-persona/ids-http-capture/<run>/`
(`NNNN_req.json/.bin`, `NNNN_resp.json/.bin`, `index.jsonl`).

While attached: sign out/in iMessage (and optionally trigger a conversation /
lookup). Compare bodies to Windows Madrid enroll to see score / identity gaps.
