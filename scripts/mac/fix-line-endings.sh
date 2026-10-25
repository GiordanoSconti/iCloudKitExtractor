#!/usr/bin/env bash
# Corregge fine riga Windows (CRLF) su script copiati dal PC.
set -e
for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "File non trovato: $f"
    continue
  fi
  sed -i '' $'s/\r$//' "$f"
  chmod +x "$f"
  echo "OK: $f"
done
