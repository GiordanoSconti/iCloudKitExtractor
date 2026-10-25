#!/usr/bin/env bash
# Client bridge sul Mac: connessione IN USCITA verso Windows (CGNAT-safe).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT="$REPO_ROOT/src/AnisetteBridge.Client/AnisetteBridge.Client.csproj"
LOCAL_BIN="$SCRIPT_DIR/anisette-bridge-client"

: "${ANISETTE_BRIDGE_SERVER_HOST:?Imposta IP pubblico statico Windows}"
: "${ANISETTE_BRIDGE_TOKEN:?Stesso token in bridge-token.txt (Windows)}"

export ANISETTE_BRIDGE_SERVER_PORT="${ANISETTE_BRIDGE_SERVER_PORT:-6971}"
export ANISETTE_LOCAL_URL="${ANISETTE_LOCAL_URL:-http://127.0.0.1:6969/}"
export ANISETTE_BRIDGE_RECONNECT_SEC="${ANISETTE_BRIDGE_RECONNECT_SEC:-5}"

if ! curl -sf --max-time 3 "${ANISETTE_LOCAL_URL}" >/dev/null 2>&1; then
  echo "Anisette Docker non risponde su ${ANISETTE_LOCAL_URL}"
  echo "Avvia prima: bash setup-anisette-v3.sh"
  exit 1
fi

run_client() {
  if [ -x "$LOCAL_BIN" ]; then
    exec "$LOCAL_BIN"
  fi
  if [ -f "$PROJECT" ] && command -v dotnet >/dev/null 2>&1; then
    exec dotnet run --project "$PROJECT" -c Release
  fi
  echo "Client bridge non trovato."
  echo "Opzione A - repo completo sul Mac:"
  echo "  git clone ... && cd iCloudKitExtractor && bash scripts/mac/start-anisette-bridge-client.sh"
  echo "Opzione B - binary nella stessa cartella dello script:"
  echo "  dotnet publish src/AnisetteBridge.Client -c Release -r osx-arm64 --self-contained"
  echo "  cp .../publish/anisette-bridge-client $LOCAL_BIN"
  exit 1
}

echo "Bridge client -> ${ANISETTE_BRIDGE_SERVER_HOST}:${ANISETTE_BRIDGE_SERVER_PORT}"
echo "Anisette locale: ${ANISETTE_LOCAL_URL}"
run_client
