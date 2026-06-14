#!/usr/bin/env bash
# CCO Live Lab Validation — mcp-hunter zincirini kasıtlı-zafiyetli loopback hedefe karşı
# gerçekten (live=True) doğrular. Kali'de de aynen çalışır.
#
# Kullanım:
#   bash scripts/lab-validate.sh
#
# Not: Sadece 127.0.0.1'e bağlanır; gerçek/yetkisiz bir hedefe DOKUNMAZ.
#      RAG inline hit'leri için chromadb gerekir (yoksa enrich plan modunu doğrular).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

echo "🔬 CCO Live Lab Validation başlıyor (loopback, yetkili)…"
python3 -c "import chromadb" 2>/dev/null && echo "  chromadb: ✓ (RAG inline aktif)" \
  || echo "  chromadb: ✗ (enrich plan modu — 'pip install chromadb' ile inline açılır)"
echo ""
exec python3 "$REPO/scripts/lab-validate.py"
