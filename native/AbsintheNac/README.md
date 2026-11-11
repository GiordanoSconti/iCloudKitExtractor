# Native Absinthe NAC (macOS)

Generates IDS `validation-data` by calling **NACInit / NACKeyEstablishment / NACSign**
inside `identityservicesd` (same approach as Beeper `mac-registration-provider`).

On Apple Silicon this is the real Absinthe path — no `data.plist` / Unicorn spoof.

## Status (macOS 27.2 / 26B123 arm64e)

| Symbol | File VA | Notes |
|--------|---------|-------|
| Ref `IDSProtoKeyTransparencyTrustedServiceReadFrom` | `0x1002aef94` | slide base |
| **NACInit** | `0x10080cd50` | sanity `-44023`; produces session-info-request |
| **NACKeyEstablishment** | `0x100803720` | returns 0 after `initializeValidation` |
| **NACSign** | *TBD* | not yet pinned on 27.2 (Absinthe V4). Until set, relay falls back to pypush Unicorn |

`identityservicesd` sha256:
`cb97f17df6dfccad1a07f91b87dfe764d8fabeeaf2e9b760ea8892a391986f04`

## CLI

```bash
python3 native/AbsintheNac/absinthe_nac.py --json
```

## Relay

AnisetteServer.Mac `/validation-data` uses backend order:

1. `absinthe` — this helper (when Sign offset is known / generation succeeds)
2. `pypush` — `scripts/nac-pypush` Unicorn fallback

Override: settings `nacBackend` = `auto` | `absinthe` | `pypush`, or env `IKE_NAC_BACKEND`.
