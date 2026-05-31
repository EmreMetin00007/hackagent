#!/bin/bash
# ════════════════════════════════════════════════════════════════
# cco-profile.sh — MCP Profil Değiştirici (TOKEN TASARRUFU)
# ════════════════════════════════════════════════════════════════
# Claude Code her istekte TÜM kayıtlı MCP server'ların tool şemalarını
# context'e yükler (~28K token / 187 tool). Göreve göre yalnızca ilgili
# server'ları yükleyerek istek başına 10-20K token tasarruf edilir.
#
# Kullanım:
#   bash scripts/cco-profile.sh <profil>
#   profiller: min | recon | web | llm | ctf | ad | full | list
#
# NOT: Profil değişikliği yeni bir `claude` oturumunda etkili olur.
# ════════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CCO_DIR="$(dirname "$SCRIPT_DIR")"
REAL_HOME="${HOME}"
CLAUDE_JSON="$REAL_HOME/.claude.json"
CCO_DATA_DIR="${CCO_HOME:-$REAL_HOME/.cco}"

G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; R='\033[0;31m'; N='\033[0m'

PROFILE="${1:-list}"

if [ "$PROFILE" = "list" ] || [ -z "$PROFILE" ]; then
  echo -e "${C}CCO MCP Profilleri (token tasarrufu):${N}"
  echo -e "  ${G}min${N}    → kali, memory, telemetry            (~15K tok)"
  echo -e "  ${G}recon${N}  → kali, osint, browser, memory, tel  (~17K tok, %37↓)"
  echo -e "  ${G}web${N}    → kali, web-advanced, llm-sec, browser, memory, rag, tel (~21K)"
  echo -e "  ${G}llm${N}    → llm-sec, browser, web-advanced, memory, tel  (~8K tok, %71↓)"
  echo -e "  ${G}ctf${N}    → kali, ctf-platform, memory, rag, tel  (~17K tok)"
  echo -e "  ${G}ad${N}     → kali, ad-tools, container, memory, tel  (~18K tok)"
  echo -e "  ${G}full${N}   → 11 server (varsayılan)             (~28K tok)"
  echo ""
  echo -e "Kullanım: ${Y}bash scripts/cco-profile.sh llm${N}"
  echo -e "Maliyet:  ${Y}python3 scripts/token-estimate.py${N}"
  exit 0
fi

# Profil → server listesi (+ kali-tools alt-grupları: ekstra token tasarrufu)
case "$PROFILE" in
  min)   SERVERS="kali-tools memory-server telemetry"; KALI_GROUPS="core" ;;
  recon) SERVERS="kali-tools osint-tools browser memory-server telemetry"; KALI_GROUPS="core,osint,swarm" ;;
  web)   SERVERS="kali-tools web-advanced llm-security browser memory-server rag-engine telemetry"; KALI_GROUPS="core,web,exploit,llm,report" ;;
  llm)   SERVERS="llm-security browser web-advanced memory-server telemetry"; KALI_GROUPS="" ;;
  ctf)   SERVERS="kali-tools ctf-platform memory-server rag-engine telemetry"; KALI_GROUPS="core,web,pwn,exploit" ;;
  ad)    SERVERS="kali-tools ad-tools container-tools memory-server telemetry"; KALI_GROUPS="core,ad,exploit,swarm" ;;
  full)  SERVERS="kali-tools web-advanced ctf-platform ad-tools memory-server container-tools osint-tools telemetry browser rag-engine llm-security"; KALI_GROUPS="all" ;;
  *) echo -e "${R}Bilinmeyen profil: $PROFILE${N} (geçerli: min recon web llm ctf ad full list)"; exit 1 ;;
esac

if [ ! -f "$CLAUDE_JSON" ]; then
  echo -e "${R}HATA: $CLAUDE_JSON yok. Önce ./install-cco.sh çalıştır.${N}"; exit 1
fi

cp "$CLAUDE_JSON" "$CLAUDE_JSON.bak.$(date +%s)"

CCO_DIR="$CCO_DIR" CCO_DATA_DIR="$CCO_DATA_DIR" SERVERS="$SERVERS" PROFILE="$PROFILE" KALI_GROUPS="$KALI_GROUPS" \
python3 <<'PYEOF'
import json, os

cco_dir   = os.environ["CCO_DIR"]
data_dir  = os.environ["CCO_DATA_DIR"]
servers   = os.environ["SERVERS"].split()
profile   = os.environ["PROFILE"]
kali_grp  = os.environ.get("KALI_GROUPS", "").strip()
path      = os.path.join(os.path.expanduser("~"), ".claude.json")

# Server'a özel env tanımları
def env_for(name):
    if name == "kali-tools":
        env = {"CCO_HOME": data_dir,
               "CCO_ANALYZE_MODEL": "qwen/qwen3.6-plus",
               "CCO_EXPLOIT_MODEL": "nousresearch/hermes-4-405b"}
        # Profil kali alt-grubu belirttiyse ekle (token tasarrufu)
        if kali_grp:
            env["CCO_KALI_GROUPS"] = kali_grp
        return env
    if name == "ctf-platform":
        return {"CTFD_URL": "", "CTFD_TOKEN": "", "HTB_TOKEN": "", "THM_TOKEN": ""}
    if name == "osint-tools":
        return {"CCO_HOME": data_dir, "GITHUB_TOKEN": ""}
    return {"CCO_HOME": data_dir}

# Mevcut config'i koru, sadece mcpServers'ı güncelle
existing = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            existing = json.load(f)
    except Exception:
        existing = {}

# Önceki env değerlerini (ör. doldurulmuş token'lar) koru
prev = existing.get("mcpServers", {})

mcp_servers = {}
for name in servers:
    key = name.replace("mcp-", "")
    env = env_for(name)
    # Kullanıcı daha önce token girdiyse koru — AMA sadece yeni env'de BOŞ olan
    # placeholder'ları doldur. Profile-türevli değerleri (CCO_KALI_GROUPS, CCO_HOME,
    # model adları) ASLA ezme; onlar her profil değişiminde yeniden hesaplanmalı.
    if key in prev and isinstance(prev[key].get("env"), dict):
        for k, v in prev[key]["env"].items():
            if v and k in env and not env[k]:
                env[k] = v
    mcp_servers[key] = {
        "command": "python3",
        "args": [os.path.join(cco_dir, "mcp-servers", f"mcp-{name}", "server.py")],
        "env": env,
    }

existing["mcpServers"] = mcp_servers
with open(path, "w") as f:
    json.dump(existing, f, indent=2)
print(f"  profil '{profile}': {len(mcp_servers)} server aktif → {', '.join(mcp_servers.keys())}")
PYEOF

echo ""
echo -e "${G}✓ MCP profili '${PROFILE}' uygulandı.${N}"
echo -e "${Y}→ Etkili olması için yeni bir oturum başlat: ${C}claude${N}"
echo -e "${Y}→ Token maliyetini gör: ${C}python3 scripts/token-estimate.py${N}"
