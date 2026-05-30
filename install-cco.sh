#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   🔴 CCO — Claude Code Offensive Operator
#   Kali Linux + OpenRouter + 6 MCP Server — Tek Komut Kurulum
# ═══════════════════════════════════════════════════════════════
# Kullanım:
#   git clone https://github.com/EmreMetin00007/AgentCracker.git cco
#   cd cco
#   chmod +x install-cco.sh
#   ./install-cco.sh
#
# Bu script:
#   1. Kali güvenlik araçlarını kurar (nmap, sqlmap, nuclei, ...)
#   2. Python MCP bağımlılıklarını kurar (mcp, chromadb, ...)
#   3. Claude Code CLI'ı kurar (npm -g @anthropic-ai/claude-code)
#   4. ~/.cco veri dizinini oluşturur
#   5. OpenRouter API key'ini .env dosyasına kaydeder
#   6. ~/.claude.json'a 6 MCP server'ı kaydeder (mevcut dosya yedeklenir)
#   7. system_prompt.md → CLAUDE.md'ye kopyalar (yoksa)

set -e

# ── Renkler ────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1;37m'; N='\033[0m'

CCO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Gerçek kullanıcı tespiti (sudo ile çalışabilir)
if [ -n "$SUDO_USER" ]; then
  REAL_USER="$SUDO_USER"
  REAL_HOME=$(eval echo "~$SUDO_USER")
else
  REAL_USER="${USER:-$(whoami)}"
  REAL_HOME="$HOME"
fi

CCO_DATA_DIR="$REAL_HOME/.cco"

echo -e "${R}"
cat << 'BANNER'
  ╔═══════════════════════════════════════════════╗
  ║                                               ║
  ║   🔴  C C O   v 2 . 0                         ║
  ║                                               ║
  ║   Claude Code Offensive Operator              ║
  ║   OpenRouter × Claude Code × MCP × Kali       ║
  ║                                               ║
  ╚═══════════════════════════════════════════════╝
BANNER
echo -e "${N}"
echo -e "${B}Kullanıcı:${N}   $REAL_USER"
echo -e "${B}Home:${N}        $REAL_HOME"
echo -e "${B}Repo:${N}        $CCO_DIR"
echo -e "${B}Veri:${N}        $CCO_DATA_DIR"
echo ""

# ═══════════════════════════════════════════════════════════════
# 1. KALİ GÜVENLİK ARAÇLARI
# ═══════════════════════════════════════════════════════════════
echo -e "${C}━━━ [1/7] Kali güvenlik araçları ━━━${N}"

if command -v apt-get &>/dev/null; then
  SUDO=""
  [ "$EUID" -ne 0 ] && SUDO="sudo"
  $SUDO apt-get update -q
  $SUDO apt-get install -y -q \
    nmap sqlmap ffuf nikto nuclei hydra hashcat john \
    gobuster dirb wfuzz whatweb netcat-openbsd \
    curl wget git python3 python3-pip nodejs npm \
    gdb binwalk foremost steghide \
    libimage-exiftool-perl tshark \
    2>/dev/null || echo -e "${Y}  ⚠ Bazı paketler kurulamadı (Kali değilse normal)${N}"

  # Opsiyonel paketler
  $SUDO apt-get install -y -q subfinder amass wpscan crackmapexec \
    seclists wordlists enum4linux smbclient 2>/dev/null || true

  # rockyou.txt unzip
  if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    (cd /usr/share/wordlists && $SUDO gunzip -kf rockyou.txt.gz 2>/dev/null || true)
  fi
  echo -e "${G}  ✓ Kali araçları kuruldu${N}"
else
  echo -e "${Y}  ⚠ apt-get yok — Kali Linux dışı sistem, bu adım atlanıyor${N}"
fi

# ═══════════════════════════════════════════════════════════════
# 2. PYTHON MCP BAĞIMLILIKLARI
# ═══════════════════════════════════════════════════════════════
echo -e "${C}━━━ [2/7] Python MCP bağımlılıkları ━━━${N}"

PIP_ARGS="--quiet"
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
  PIP_ARGS="--quiet --break-system-packages"
fi

pip3 install $PIP_ARGS \
  'mcp[cli]>=1.0' \
  'fastmcp' \
  'requests>=2.31' \
  'networkx>=3.0' \
  'chromadb>=0.4' \
  'pycryptodome>=3.19' \
  'PyYAML>=6.0' \
  'beautifulsoup4>=4.12' \
  'dnspython' \
  'aiohttp' \
  'python-whois' \
  'xmltodict' 2>&1 | tail -5 || true

echo -e "${G}  ✓ Python bağımlılıkları kuruldu${N}"

# ═══════════════════════════════════════════════════════════════
# 3. VERİ DİZİNİ
# ═══════════════════════════════════════════════════════════════
echo -e "${C}━━━ [3/7] Veri dizini ━━━${N}"

mkdir -p "$CCO_DATA_DIR"/{logs,sessions,rag,memory,loot,approvals,web_advanced,screenshots}
if [ "$EUID" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
  chown -R "$REAL_USER:$REAL_USER" "$CCO_DATA_DIR"
fi
echo -e "${G}  ✓ $CCO_DATA_DIR hazır${N}"

# ── Skills → ~/.claude/skills symlinks (Agent Skills discovery) ──
# Claude Code, ~/.claude/skills/<name>/SKILL.md dosyalarını otomatik
# bulur ve /<name> slash command olarak sunar. CCO skill'leri
# repo içinde /.claude/skills/ altında tutulur; buradan symlink ile
# global skill havuzuna bağlanır.
echo -e "${C}  → Skills global skill havuzuna bağlanıyor...${N}"
mkdir -p "$REAL_HOME/.claude/skills"
for skill_dir in "$CCO_DIR/.claude/skills/"*/; do
  [ -d "$skill_dir" ] || continue
  name=$(basename "$skill_dir")
  target="$REAL_HOME/.claude/skills/$name"
  if [ ! -e "$target" ]; then
    ln -sfn "$skill_dir" "$target" 2>/dev/null && echo -e "${G}    ✓ /$name${N}"
  else
    echo -e "${Y}    ⚠ /$name zaten var (atlanıyor)${N}"
  fi
done
if [ "$EUID" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
  chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/.claude/skills"
fi

# ═══════════════════════════════════════════════════════════════
# 4. CLAUDE CODE CLI
# ═══════════════════════════════════════════════════════════════
echo -e "${C}━━━ [4/7] Claude Code CLI ━━━${N}"

if command -v claude &>/dev/null; then
  echo -e "${G}  ✓ Zaten kurulu: $(claude --version 2>/dev/null | head -1)${N}"
else
  echo -e "${C}  → npm ile kuruluyor...${N}"
  if command -v npm &>/dev/null; then
    npm install -g @anthropic-ai/claude-code 2>&1 | tail -3
    echo -e "${G}  ✓ Claude Code kuruldu: $(claude --version 2>/dev/null | head -1)${N}"
  else
    echo -e "${R}  ✗ npm yok — önce Node.js kurun: apt install nodejs npm${N}"
    exit 1
  fi
fi

# ═══════════════════════════════════════════════════════════════
# 5. OPENROUTER API KEY + .env
# ═══════════════════════════════════════════════════════════════
echo -e "${C}━━━ [5/7] .env konfigürasyonu ━━━${N}"

if [ ! -f "$CCO_DIR/.env" ]; then
  if [ -f "$CCO_DIR/.env.example" ]; then
    cp "$CCO_DIR/.env.example" "$CCO_DIR/.env"
    echo -e "${C}  → .env.example → .env kopyalandı${N}"
  fi
fi

# Eğer .env'de key YOK veya placeholder varsa sor
NEEDS_KEY=1
if [ -f "$CCO_DIR/.env" ]; then
  if grep -qE "^ANTHROPIC_AUTH_TOKEN=sk-or-v1-[A-Za-z0-9]{20,}" "$CCO_DIR/.env"; then
    NEEDS_KEY=0
    echo -e "${G}  ✓ OpenRouter API key zaten set${N}"
  fi
fi

if [ "$NEEDS_KEY" = "1" ]; then
  echo ""
  echo -e "${Y}  OpenRouter API Key gerekli.${N}"
  echo -e "${C}  → Key al: ${B}https://openrouter.ai/keys${N}"
  read -p "  OpenRouter API Key (sk-or-v1-...): " OR_KEY
  if [ -n "$OR_KEY" ]; then
    # Replace both ANTHROPIC_AUTH_TOKEN and OPENROUTER_API_KEY
    sed -i "s|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=$OR_KEY|" "$CCO_DIR/.env"
    sed -i "s|^OPENROUTER_API_KEY=.*|OPENROUTER_API_KEY=$OR_KEY|" "$CCO_DIR/.env"
    chmod 600 "$CCO_DIR/.env"
    [ "$EUID" -eq 0 ] && [ "$REAL_USER" != "root" ] && chown "$REAL_USER:$REAL_USER" "$CCO_DIR/.env"
    echo -e "${G}  ✓ API key .env'e kaydedildi${N}"
  else
    echo -e "${Y}  ⚠ Key boş bırakıldı. Sonra $CCO_DIR/.env düzenleyin.${N}"
  fi
fi

# ═══════════════════════════════════════════════════════════════
# 6. ~/.claude.json — MCP SERVER KAYIT
# ═══════════════════════════════════════════════════════════════
echo -e "${C}━━━ [6/7] ~/.claude.json MCP kaydı ━━━${N}"

CLAUDE_JSON="$REAL_HOME/.claude.json"

# Mevcut dosyayı yedekle
if [ -f "$CLAUDE_JSON" ]; then
  BAK="$CLAUDE_JSON.bak.$(date +%Y%m%d%H%M%S)"
  cp "$CLAUDE_JSON" "$BAK"
  echo -e "${C}  → Mevcut ~/.claude.json yedeklendi: $BAK${N}"
fi

# Python ile merge et (mevcut projeleri koru, sadece mcpServers güncelle)
python3 <<PYEOF
import json, os
path = "$CLAUDE_JSON"
existing = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            existing = json.load(f)
    except Exception:
        existing = {}

mcp_servers = {
    "kali-tools": {
        "command": "python3",
        "args": ["$CCO_DIR/mcp-servers/mcp-kali-tools/server.py"],
        "env": {
            "CCO_HOME": "$CCO_DATA_DIR",
            "CCO_ANALYZE_MODEL": "qwen/qwen3.6-plus",
            "CCO_EXPLOIT_MODEL": "nousresearch/hermes-4-405b"
        }
    },
    "memory-server": {
        "command": "python3",
        "args": ["$CCO_DIR/mcp-servers/mcp-memory-server/server.py"],
        "env": {"CCO_HOME": "$CCO_DATA_DIR"}
    },
    "ctf-platform": {
        "command": "python3",
        "args": ["$CCO_DIR/mcp-servers/mcp-ctf-platform/server.py"],
        "env": {"CTFD_URL": "", "CTFD_TOKEN": "", "HTB_TOKEN": "", "THM_TOKEN": ""}
    },
    "web-advanced": {
        "command": "python3",
        "args": ["$CCO_DIR/mcp-servers/mcp-web-advanced/server.py"],
        "env": {"CCO_HOME": "$CCO_DATA_DIR"}
    },
    "rag-engine": {
        "command": "python3",
        "args": ["$CCO_DIR/mcp-servers/mcp-rag-engine/server.py"],
        "env": {"CCO_HOME": "$CCO_DATA_DIR"}
    },
    "telemetry": {
        "command": "python3",
        "args": ["$CCO_DIR/mcp-servers/mcp-telemetry/server.py"],
        "env": {"CCO_HOME": "$CCO_DATA_DIR"}
    }
}

existing["mcpServers"] = mcp_servers
with open(path, "w") as f:
    json.dump(existing, f, indent=2)
print(f"  ✓ 6 MCP server kaydedildi → {path}")
PYEOF

if [ "$EUID" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
  chown "$REAL_USER:$REAL_USER" "$CLAUDE_JSON"
fi

# ═══════════════════════════════════════════════════════════════
# 7. CLAUDE.md + DOĞRULAMA
# ═══════════════════════════════════════════════════════════════
echo -e "${C}━━━ [7/7] CLAUDE.md + doğrulama ━━━${N}"

if [ -f "$CCO_DIR/CLAUDE.md" ]; then
  echo -e "${G}  ✓ CLAUDE.md zaten mevcut${N}"
else
  echo -e "${Y}  ⚠ CLAUDE.md bulunamadı — repodan çekilmemiş olabilir${N}"
fi

# Test importları
echo -e "${C}  → MCP server import testleri...${N}"
for srv in kali-tools memory-server telemetry rag-engine ctf-platform web-advanced; do
  pyfile="$CCO_DIR/mcp-servers/mcp-$srv/server.py"
  if [ -f "$pyfile" ]; then
    if python3 -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('s', '$pyfile')
m = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m); print('ok')
except Exception as e:
    print(f'FAIL: {type(e).__name__}: {e}'); sys.exit(1)
" &>/dev/null; then
      echo -e "${G}    ✓ mcp-$srv${N}"
    else
      echo -e "${R}    ✗ mcp-$srv (import hatası — bağımlılık eksik)${N}"
    fi
  fi
done

echo ""
echo -e "${R}╔═══════════════════════════════════════════════╗${N}"
echo -e "${R}║  ✅  CCO Kurulumu Tamamlandı                  ║${N}"
echo -e "${R}╚═══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${Y}Başlatmak için:${N}"
echo -e "  ${B}cd $CCO_DIR${N}"
echo -e "  ${B}source .env${N}"
echo -e "  ${B}claude${N}                    ${C}# İnteraktif REPL${N}"
echo ""
echo -e "${Y}İlk test:${N}"
echo -e "  ${B}claude -p \"/tools\"${N}      ${C}# MCP araçlarını listele${N}"
echo -e "  ${B}claude -p \"hangi mcp araçlarına erişimin var?\"${N}"
echo ""
echo -e "${Y}Veri dizini:${N}  $CCO_DATA_DIR"
echo -e "${Y}Config:${N}       $CCO_DIR/.env"
echo -e "${Y}MCP kayıt:${N}    $CLAUDE_JSON"
echo ""
echo -e "${R}⚠️  Yalnızca yetkili hedeflere karşı kullanın.${N}"
