#!/usr/bin/env bash
# Crea manifest.json da lib estratte a mano (ipsw dyld split / extract).
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PY="$REPO_ROOT/scripts/akd-adi-worker/create_ios_adi_manifest.py"

if [ $# -lt 1 ]; then
  echo "Uso:"
  echo "  $0 --scan /path/cartella_split"
  echo "  $0 --coreadi /path/CoreADI --storeservices /path/StoreServices"
  echo ""
  echo "Esempio dopo ipsw dyld split:"
  echo "  $0 --scan ~/ipsw_dyld/23F84__iPhone18,2/_split"
  exit 1
fi

python3 "$PY" "$@"
