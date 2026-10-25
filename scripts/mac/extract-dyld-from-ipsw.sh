#!/usr/bin/env bash
# Estrae dyld_shared_cache da IPSW su Mac (ipsw CLI).
# Uso:
#   bash scripts/mac/extract-dyld-from-ipsw.sh /path/to/iPhone_Restore.ipsw
#   bash scripts/mac/extract-dyld-from-ipsw.sh /path/to/file.ipsw ~/ipsw_dyld
set -eu
set -o pipefail 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

IPSW="${1:-}"
OUT="${2:-$HOME/ipsw_dyld}"
SKIP_ADI="${SKIP_ADI_LIBS:-0}"

if [ -z "$IPSW" ]; then
  echo "Uso: $0 <file.ipsw> [cartella_output]"
  echo "Es.: $0 ~/Downloads/iPhone18_2_26.5.2_23F84_Restore.ipsw"
  exit 1
fi

if [ ! -f "$IPSW" ]; then
  echo "IPSW non trovato: $IPSW"
  exit 1
fi

if ! command -v ipsw >/dev/null 2>&1; then
  echo "Installazione ipsw…"
  if command -v brew >/dev/null 2>&1; then
    brew install blacktop/tap/ipsw
  else
    echo "Installa Homebrew (https://brew.sh) oppure scarica ipsw da:"
    echo "  https://github.com/blacktop/ipsw/releases"
    exit 1
  fi
fi

mkdir -p "$OUT"
echo "=== Passo 1/2: dyld_shared_cache dall'IPSW (10–20 min) ==="
echo "IPSW:  $IPSW"
echo "Output: $OUT"
echo ""
echo "NOTA: questo passo NON crea manifest.json — solo il passo 2 (CoreADI)."
echo ""

ipsw extract --dyld "$IPSW" -o "$OUT"

MAIN=""
EXTRA=""
while IFS= read -r line; do
  if [ -z "$MAIN" ]; then
    MAIN="$line"
  else
    EXTRA="${EXTRA}${EXTRA:+
}${line}"
  fi
done <<EOF
$(find "$OUT" -name 'dyld_shared_cache_arm64*' -type f ! -name '*symbols*' 2>/dev/null | sort)
EOF

if [ -z "$MAIN" ]; then
  echo "ERRORE: dyld_shared_cache_arm64* non trovato in $OUT"
  exit 1
fi

echo ""
echo "=== Passo 1 completato ==="
echo "File principale:"
echo "  $MAIN"
if [ -n "$EXTRA" ]; then
  echo ""
  echo "Subcache (tenere nella stessa cartella per ipsw):"
  echo "$EXTRA" | sed 's/^/  /'
fi

if [ "$SKIP_ADI" = "1" ]; then
  echo ""
  echo "SKIP_ADI_LIBS=1 — passo 2 saltato."
  echo "Esegui: bash scripts/mac/extract-ios-adi-libs.sh \"$MAIN\""
  exit 0
fi

echo ""
echo "=== Passo 2/2: CoreADI + StoreServices → manifest.json ==="
bash "$SCRIPT_DIR/extract-ios-adi-libs.sh" "$MAIN"
