#!/usr/bin/env bash
# Cerca CoreADI / StoreServices: tutti i DSC, split, Simulator Xcode.
set -eu
set -o pipefail 2>/dev/null || true

SEARCH_ROOT="${1:-$HOME/ipsw_dyld}"

echo "=== Cerca CoreADI ovunque ==="
echo ""

found=0

echo "--- 1) File Mach-O già estratti (split / extract) ---"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  found=1
  echo "  $f ($(stat -f%z "$f" 2>/dev/null || stat -c%s "$f") bytes)"
done < <(find "$HOME/ios-adi-split" "$HOME/ios-adi-extract" "$SEARCH_ROOT" \
  \( -path '*/CoreADI.framework/CoreADI' -o -path '*/StoreServices.framework/StoreServices' \) \
  -type f 2>/dev/null | sort -u)
[ "$found" -eq 0 ] && echo "  (nessuno)"
echo ""

echo "--- 2) Tutti i dyld_shared_cache (IPSW può averne diversi: system + cryptex) ---"
DSC_COUNT=0
while IFS= read -r dsc; do
  [ -z "$dsc" ] && continue
  DSC_COUNT=$((DSC_COUNT + 1))
  [ "$DSC_COUNT" -gt 40 ] && break
  echo ""
  echo "  DSC: $dsc"
  echo "  dir: $(ls "$(dirname "$dsc")"/dyld_shared_cache* 2>/dev/null | wc -l | tr -d ' ') file dyld*"
  if command -v ipsw >/dev/null 2>&1; then
    hits="$(ipsw dyld image "$dsc" 2>/dev/null | grep -iE 'coreadi|storeservices' | head -5 || true)"
    if [ -n "$hits" ]; then
      echo "  MATCH image:"
      echo "$hits" | sed 's/^/    /'
    else
      str_hits="$(ipsw dyld str "$dsc" CoreADI 2>/dev/null | head -3 || true)"
      if [ -n "$str_hits" ]; then
        echo "  MATCH str CoreADI:"
        echo "$str_hits" | sed 's/^/    /'
      else
        echo "  (nessun CoreADI/StoreServices in image/str)"
      fi
    fi
  fi
done < <(find "$SEARCH_ROOT" -name 'dyld_shared_cache_arm64*' -type f ! -name '*symbols*' 2>/dev/null | sort -u)

if [ "$DSC_COUNT" -eq 0 ]; then
  echo "  Nessun DSC sotto $SEARCH_ROOT"
  echo "  Riesegui: ipsw extract --dyld file.ipsw -o ~/ipsw_dyld"
fi
echo ""

echo "--- 3) iOS Simulator (Xcode) — spesso ha CoreADI come file singolo ---"
sim_found=0
for base in \
  "/Library/Developer/CoreSimulator/Volumes" \
  "$HOME/Library/Developer/CoreSimulator/Volumes" \
  "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform" \
  ; do
  [ -d "$base" ] || continue
  while IFS= read -r f; do
    sim_found=1
    echo "  $f"
  done < <(find "$base" \( -path '*/CoreADI.framework/CoreADI' -o -path '*/StoreServices.framework/StoreServices' \) -type f 2>/dev/null | head -10)
done
[ "$sim_found" -eq 0 ] && echo "  (nessuno — installa Xcode + iOS Simulator runtime)"
echo ""

echo "--- 4) Cosa fare ---"
cat <<'EOF'

Se CoreADI non è in NESSUN dyld_shared_cache_arm64e:

  A) L'IPSW iOS 26 ha cache SEPARATE (Cryptex). Estrai TUTTI i dyld:
       rm -rf ~/ipsw_dyld
       ipsw extract --dyld ~/Downloads/iPhone18_2_26.5.2_23F84_Restore.ipsw -o ~/ipsw_dyld
       find ~/ipsw_dyld -name 'dyld_shared_cache*' ! -name '*symbols*'
       bash scripts/mac/find-coreadi-everywhere.sh ~/ipsw_dyld

  B) Usa iOS Simulator (se hai Xcode) — Mach-O iOS, spesso estraibile:
       xcodebuild -downloadPlatform iOS
       find /Library/Developer/CoreSimulator/Volumes -name CoreADI 2>/dev/null
       python3 scripts/akd-adi-worker/create_ios_adi_manifest.py \
         --coreadi "<path>/CoreADI" \
         --storeservices "<path>/StoreServices" --skip-analysis

  C) Tool alternativo: dylex (Rust) — https://github.com/19h/dylex
       dylex extract -i CoreADI -o ~/ios-adi-extract <DSC_DIR>

  D) Intanto su Windows: worker Android (Anisette.py) per init; iOS ADI resta in reverse.

EOF
