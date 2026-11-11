# OctagonJoin

Standalone console tool: **join a new Octagon peer** into an Apple ID trust circle using sponsor keys recovered by IKE (`OTBottle` / Peer unlock).

It does **only** the join path (`fetchChanges` → new peer → sponsor voucher → `joinWithVoucher`). No OpenVault, no password CSV, no backup download.

## Warning

- Mutates the account’s Octagon trust graph.
- Use only on **lab / owned** Apple IDs.
- Does **not** run Escrowproxy `ENROLL` for the new bottle (PIN-recover of the joined peer needs a separate enroll). Entropy for the Cuttlefish bottle blob is saved under `--out` for lab follow-up.

## Prerequisites

1. IKE: sign in → Unlock Octagon bottle → **OTBottle / Peer keys**.
2. Sponsor artifacts in a folder:
   - `octagon_peer_signing.pkcs8`
   - `octagon_peer_encryption.pkcs8`
   - `octagon_peer_unlock_meta.json` (must contain `peerId`)
3. A session snapshot JSON (`session_latest.json` from IKE HTTP capture / secrets log) with `dsid`, `adsid`, tokens, anisette.

## Run

```bash
dotnet run --project src/OctagonJoin -- \
  --session /path/to/session_latest.json \
  --sponsor-dir /path/to/octagon_keys \
  --out /path/to/join_out
```

Outputs (under `--out`):

| File | Meaning |
|------|---------|
| `joined_peer_signing.pkcs8` / `joined_peer_encryption.pkcs8` | New peer keys |
| `octagon_join_meta.json` | peerId, bottleId, HTTP result |
| `joinWithVoucher.request.bin` / `.response.bin` | Wire dumps |
| `join_bottle_entropy.bin` | Bottle HKDF entropy (if bottle included) |

After a successful join, point IKE / OpenVault at the **joined** PKCS#8 + peerId (or copy them over the sponsor files) and run `fetchRecoverableTLKShares` / OpenVault.

## Protocol refs

OpenBubbles/rustpush `join_clique_from_escrow` → `joinWithVoucher`; Apple TrustedPeersHelper voucher / permanentInfo signing (`TPPB.*` domain separation).
