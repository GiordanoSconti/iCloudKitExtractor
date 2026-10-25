#!/usr/bin/env bash
# Anisette v3 server su Mac (Docker). Espone :6969 sulla LAN.
set -euo pipefail

PORT="${ANISETTE_PORT:-6969}"
CONTAINER_NAME="${ANISETTE_CONTAINER_NAME:-anisette-v3}"
IMAGE="dadoum/anisette-v3-server"
VOLUME="anisette-v3_data"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker non trovato. Installa Docker Desktop per Mac:"
  echo "  https://www.docker.com/products/docker-desktop/"
  exit 1
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  echo "Container $CONTAINER_NAME gia presente — riavvio..."
  docker start "$CONTAINER_NAME" >/dev/null || true
else
  echo "Avvio $IMAGE sulla porta $PORT..."
  docker run -d --restart always \
    --name "$CONTAINER_NAME" \
    -p "0.0.0.0:${PORT}:6969" \
    --volume "${VOLUME}:/home/Alcoholic/.config/anisette-v3/lib/" \
    "$IMAGE"
fi

sleep 2
LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
echo ""
echo "=== Anisette pronto ==="
echo "  Test locale:  curl -s http://127.0.0.1:${PORT}/ | head -c 200"
if [ -n "$LAN_IP" ]; then
  echo "  URL Windows:  http://${LAN_IP}:${PORT}/"
else
  echo "  URL Windows:  http://<IP_MAC>:${PORT}/"
  echo "  (trova IP: ipconfig getifaddr en0)"
fi
echo ""
echo "Sul PC Windows:"
echo '  { "serverUrl": "http://IP_MAC:'"${PORT}"'", "authMode": "iphone" }'
echo "  in %AppData%\\iCloudKitExtractor\\anisette.json"
echo ""
echo "Firewall macOS: consenti Docker sulla porta ${PORT}"
