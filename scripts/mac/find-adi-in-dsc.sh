#!/usr/bin/env bash
# Trova CoreADI / StoreServices nel dyld_shared_cache e prova l'estrazione.
set -eu
set -o pipefail 2>/dev/null || true

DSC="${1:-}"
if [ -z "$DSC" ]; then
  echo "Uso: $0 /path/dyld_shared_cache_arm64e"
  echo "Es.: $0 ~/ipsw_dyld/23F84__iPhone18,2/dyld_shared_cache_arm64e"
  exit 1
fi

if [ ! -f "$DSC" ]; then
  echo "File non trovato: $DSC"
  exit 1
fi

if ! command -v ipsw >/dev/null 2>&1; then
  echo "Installa: brew install blacktop/tap/ipsw"
  exit 1
fi

DSC="$(cd "$(dirname "$DSC")" && pwd)/$(basename "$DSC")"
DSC_DIR="$(dirname "$DSC")"

echo "=== DSC ==="
echo "$DSC"
echo ""
echo "=== Subcache nella stessa cartella (devono esserci tutti) ==="
ls -la "$DSC_DIR"/dyld_shared_cache* 2>/dev/null | head -20 || true
echo ""
echo "=== ipsw dyld info ==="
ipsw dyld info "$DSC" 2>&1 | head -25
echo ""

echo "=== Cerca CoreADI / StoreServices nell'elenco immagini ==="
IMG="$(mktemp)"
if ipsw dyld image "$DSC" >"$IMG" 2>&1; then
  grep -i coreadi "$IMG" || echo "(nessuna riga 'coreadi')"
  echo "---"
  grep -i storeservices "$IMG" || echo "(nessuna riga 'storeservices')"
else
  echo "ipsw dyld image fallito:"
  head -5 "$IMG"
fi
rm -f "$IMG"
echo ""

echo "=== Prova extract (nome corto, poi path completo) ==="
OUT="${OUT:-/tmp/adi-extract-test}"
mkdir -p "$OUT"

try_extract() {
  local label="$1"
  shift
  echo ">> $label"
  if ipsw dyld extract "$@" 2>&1; then
    find "$OUT" -type f -size +4k 2>/dev/null | head -5
    return 0
  fi
  echo "   fallito"
  return 1
}

try_extract "CoreADI (nome corto)" "$DSC" CoreADI -o "$OUT" --slide --force || true
try_extract "StoreServices (nome corto)" "$DSC" StoreServices -o "$OUT" --slide --force || true

PATHS=(
  "/System/Library/PrivateFrameworks/CoreADI.framework/CoreADI"
  "/System/Cryptexes/OS/System/Library/PrivateFrameworks/CoreADI.framework/CoreADI"
  "/System/Library/PrivateFrameworks/StoreServices.framework/StoreServices"
  "/System/Cryptexes/OS/System/Library/PrivateFrameworks/StoreServices.framework/StoreServices"
)
for P in "${PATHS[@]}"; do
  try_extract "$P" "$DSC" "$P" -o "$OUT" --slide --force || true
done

echo ""
echo "=== Altri DSC nella cartella (Cryptex / subcache) ==="
for other in "$DSC_DIR"/dyld_shared_cache*; do
  [ -f "$other" ] || continue
  [ "$other" = "$DSC" ] && continue
  echo "--- $other ---"
  ipsw dyld image "$other" 2>/dev/null | grep -iE 'coreadi|storeservices' | head -5 || echo "(nessun match)"
done

echo ""
echo "Se tutto fallisce: aggiorna ipsw (brew upgrade blacktop/tap/ipsw)"
echo "Poi incolla l'output di: ipsw dyld image \"\$DSC\" | grep -i coreadi"
