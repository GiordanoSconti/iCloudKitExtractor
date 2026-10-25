#!/usr/bin/env bash
# Estrae CoreADI + StoreServices da dyld_shared_cache (Mac).
# Scrive manifest.json in ~/Library/Application Support/iCloudKitExtractor/ios-adi-libs/
#
# Uso:
#   bash scripts/mac/extract-ios-adi-libs.sh ~/ipsw_dyld/.../dyld_shared_cache_arm64e
#   bash scripts/mac/extract-ios-adi-libs.sh   # auto-find in ~/ipsw_dyld
set -eu
set -o pipefail 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PY="$REPO_ROOT/scripts/akd-adi-worker/extract_ios_adi_libs.py"
OUT="${IOS_ADI_LIBS_OUT:-$HOME/Library/Application Support/iCloudKitExtractor/ios-adi-libs}"

find_dsc() {
  find "$HOME/ipsw_dyld" -name 'dyld_shared_cache_arm64*' -type f ! -name '*symbols*' 2>/dev/null \
    | sort \
    | head -1
}

DSC="${1:-}"
if [ -z "$DSC" ]; then
  DSC="$(find_dsc || true)"
fi

if [ -z "$DSC" ] || [ ! -f "$DSC" ]; then
  echo "ERRORE: dyld_shared_cache non trovato."
  echo ""
  echo "Il manifest.json si crea SOLO in questo passo (non nell'estrazione IPSW)."
  echo ""
  echo "Uso: $0 <percorso/dyld_shared_cache_arm64e>"
  echo "Es.: $0 ~/ipsw_dyld/23F84__iPhone18,2/dyld_shared_cache_arm64e"
  echo ""
  echo "Prima (se serve): bash scripts/mac/extract-dyld-from-ipsw.sh /path/to/file.ipsw"
  exit 1
fi

if ! python3 -c "import lief" 2>/dev/null; then
  echo "Installazione dipendenze Python…"
  python3 -m pip install -r "$REPO_ROOT/scripts/akd-adi-worker/requirements.txt"
fi

if ! command -v ipsw >/dev/null 2>&1; then
  echo "ERRORE: ipsw richiesto (LIEF pip non apre iOS 26 DSC)."
  echo "  brew install blacktop/tap/ipsw"
  exit 1
fi

if [ -d "/Applications/Xcode.app" ] && [ "$(xcode-select -p 2>/dev/null)" != "/Applications/Xcode.app/Contents/Developer" ]; then
  echo "Suggerimento: per ipsw dyld split serve Xcode completo:"
  echo "  sudo xcode-select -s /Applications/Xcode.app"
fi

export XCODE_PATH="${XCODE_PATH:-/Applications/Xcode.app}"

mkdir -p "$OUT"
echo "=== Estrazione CoreADI / StoreServices ==="
echo "DSC: $DSC"
echo "Out: $OUT"
echo "     (qui apparirà manifest.json)"
echo ""

if ! python3 "$PY" --dsc "$DSC" --out "$OUT"; then
  echo ""
  echo "ERRORE: estrazione fallita — manifest.json NON creato."
  echo "Controlla Xcode: sudo xcode-select -s /Applications/Xcode.app"
  exit 1
fi

MANIFEST="$OUT/manifest.json"
if [ ! -f "$MANIFEST" ]; then
  echo ""
  echo "ERRORE: manifest.json assente in $OUT"
  exit 1
fi

echo ""
echo "=== Fatto ==="
echo "manifest.json: $MANIFEST"
ls -la "$OUT"/*.dylib 2>/dev/null || true
echo ""
echo "Copia su Windows:"
echo "  cartella Mac: $OUT"
echo "  destinazione: %AppData%\\iCloudKitExtractor\\ios-adi-libs\\"
echo ""
echo "Poi su Windows:"
echo "  python scripts\\akd-adi-worker\\analyze_ios_adi_libs.py"
