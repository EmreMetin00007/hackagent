#!/bin/bash
# ──────────────────────────────────────────────────────────
#  budget-check.sh — OpenRouter bakiye ve kullanım raporu
# ──────────────────────────────────────────────────────────
# Kullanım:
#   source .env && ./scripts/budget-check.sh

set -e
KEY="${ANTHROPIC_AUTH_TOKEN:-$OPENROUTER_API_KEY}"
if [ -z "$KEY" ]; then
  echo "HATA: ANTHROPIC_AUTH_TOKEN veya OPENROUTER_API_KEY set edilmemiş"
  echo "→ source .env çalıştırın"
  exit 1
fi

echo "═══ OpenRouter Credit Durumu ═══════════════════════"
curl -s "https://openrouter.ai/api/v1/credits" \
  -H "Authorization: Bearer $KEY" | python3 -m json.tool

echo ""
echo "═══ Key Rate Limit Durumu ═══════════════════════"
curl -s "https://openrouter.ai/api/v1/key" \
  -H "Authorization: Bearer $KEY" | python3 -m json.tool
