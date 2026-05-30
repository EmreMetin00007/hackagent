#!/bin/bash
# ──────────────────────────────────────────────────────────
#  model-list.sh — OpenRouter üzerinde kullanılabilir modeller
# ──────────────────────────────────────────────────────────
# Kullanım:
#   source .env && ./scripts/model-list.sh [filter]
# Örnek:
#   ./scripts/model-list.sh qwen
#   ./scripts/model-list.sh hermes

FILTER="${1:-}"
KEY="${ANTHROPIC_AUTH_TOKEN:-$OPENROUTER_API_KEY}"

if [ -z "$KEY" ]; then
  echo "HATA: ANTHROPIC_AUTH_TOKEN veya OPENROUTER_API_KEY set edilmemiş"
  echo "→ source .env çalıştırın"
  exit 1
fi

curl -s "https://openrouter.ai/api/v1/models" \
  -H "Authorization: Bearer $KEY" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
models = data.get('data', [])
flt = '$FILTER'.lower()

filtered = [m for m in models if flt in m.get('id','').lower()] if flt else models
print(f'Toplam: {len(filtered)} model')
print('─' * 90)
for m in filtered[:100]:
    mid = m.get('id', '')
    ctx = m.get('context_length', 'n/a')
    pricing = m.get('pricing', {})
    p_in = pricing.get('prompt', '0')
    p_out = pricing.get('completion', '0')
    try:
        p_in_m = float(p_in) * 1_000_000
        p_out_m = float(p_out) * 1_000_000
        cost = f'\${p_in_m:.2f}/\${p_out_m:.2f}'
    except:
        cost = f'{p_in}/{p_out}'
    print(f'  {mid:60s}  ctx={str(ctx):>8s}  \$/1M={cost}')
"
