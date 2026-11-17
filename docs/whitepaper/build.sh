#!/usr/bin/env bash
# Build LaTeX + PDF from the Italian whitepaper markdown.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/whitepaper"
MD="$ROOT/whitepaper-protocolli-backup-octagon-pcs.md"
BASE="whitepaper-protocolli-backup-octagon-pcs"

TMP_MD="$(mktemp -t whitepaperXXXX).md"
sed 's|whitepaper/figures/\([^)]*\)\.png|figures/\1.png|g' "$MD" > "$TMP_MD"

cd "$OUT"

echo "==> figures"
python3 "$OUT/generate_figures.py" >/dev/null
python3 "$OUT/generate_sequence_figures.py" >/dev/null

echo "==> pandoc → $BASE.tex"
pandoc "$TMP_MD" \
  -f markdown \
  -t latex \
  --standalone \
  -V documentclass=article \
  -V classoption=10pt \
  -V lang=en \
  -H "$OUT/header.tex" \
  --resource-path="$OUT:$ROOT" \
  -o "$OUT/$BASE.tex"

sed -i.bak 's|figures/\([^}]*\)\.png|figures/\1.pdf|g' "$OUT/$BASE.tex"
rm -f "$OUT/$BASE.tex.bak"

echo "==> pandoc → $BASE.typ + typst compile → $BASE.pdf"
pandoc "$TMP_MD" \
  -f markdown \
  -t typst \
  --resource-path="$OUT" \
  -o "$OUT/${BASE}.body.typ"

{
  cat "$OUT/typst-preamble.typ"
  echo
  cat "$OUT/${BASE}.body.typ"
} > "$OUT/$BASE.typ"

typst compile --root "$OUT" "$OUT/$BASE.typ" "$OUT/$BASE.pdf"

rm -f "$TMP_MD" "$OUT/${BASE}.body.typ"
ls -lh "$OUT/$BASE.tex" "$OUT/$BASE.typ" "$OUT/$BASE.pdf"
echo "OK: $OUT/$BASE.pdf"
