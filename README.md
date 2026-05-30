# 🔴 CCO — Claude Code Offensive Operator

> Otonom bug bounty avcısı & CTF çözücü. **Claude Code CLI** orkestrasyonu,
> **OpenRouter** üzerinden ucuz/sansürsüz modeller, **10 MCP server** ile 181
> güvenlik aracı. Kali Linux için.

**v3.1 HackerAgent → v2.0 CCO geçişi:** 4.327 satır Python orkestrasyon kodu
silindi; tüm orkestrasyon Claude Code'a bırakıldı. Sadece MCP tool'lar, skills,
workflows ve rules kaldı.

---

## ⚡ Tek Komutla Kurulum

```bash
git clone https://github.com/EmreMetin00007/AgentCracker.git cco
cd cco
chmod +x install-cco.sh
./install-cco.sh
# Kurulum sırasında OpenRouter API key'iniz sorulur
```

`install-cco.sh` şunları yapar:
- ✅ Kali güvenlik araçları (nmap, sqlmap, ffuf, nuclei, hashcat, john, ...)
- ✅ Python MCP bağımlılıkları (mcp, chromadb, networkx, dnspython, ...)
- ✅ Claude Code CLI kurulumu (npm -g @anthropic-ai/claude-code)
- ✅ `~/.cco/` veri dizini (DB, loglar, RAG, approvals)
- ✅ `.env` dosyası (OpenRouter yönlendirmesi)
- ✅ `~/.claude.json` — 10 MCP server kaydı (mevcut dosya yedeklenir)

---

## 🏁 Başlatma

```bash
cd /path/to/cco
source .env
claude
```

İlk komutlar (slash command'la başlamak en garantili yol):
```
> /tools                                         # Tüm MCP araçlarını listele
> /recon-enumeration scanme.nmap.org             # Keşif skill'ini tetikle
> /web-exploit testphp.vulnweb.com/?test=query   # Web zafiyet skill'i
> /ctf-solver picoCTF Binary Exploitation        # CTF orkestratör
> 10.10.10.10 hedefini tara                      # Doğal dil de çalışır
```

**Neden slash command önerilir?** Gerçek testlerde model tool-use davranışı
orkestrator modele göre değişiyor (Llama 3.3 70B `Skill` tool'unu düzgün çağırıyor,
Qwen3-next-80b bazen sadece metin yazıyor). Slash command Claude Code tarafında
handle edilir ve modelden bağımsız olarak her zaman skill'i tetikler.

---

## 🏗️ Mimari

```
┌─────────────────────────────────────────────┐
│         Kullanıcı (Kali Terminal)           │
│         source .env && claude               │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│         Claude Code CLI                     │
│  • Orkestrasyon, OODA loop, tool routing    │
│  • CLAUDE.md → hacker persona + metodoloji  │
│  • ~/.claude.json → 10 MCP server kaydı     │
└──────┬──────────────┬───────────────────────┘
       │              │
       ▼              ▼
┌────────────┐  ┌─────────────────────────────────┐
│ OpenRouter │  │      MCP Server'lar (10)        │
│   API      │  │  ┌──────────────────────────┐   │
│            │  │  │ mcp-kali-tools  (76 tool) │   │
│ Session:   │  │  │ mcp-web-advanced (25 tool)│   │
│ qwen3-next │  │  │ mcp-ctf-platform (14 tool)│   │
│ 80b-a3b    │  │  │ mcp-ad-tools    (12 tool) │   │
│            │  │  │ mcp-memory-srv  (10 tool) │   │
│ Tool içi:  │  │  │ mcp-container   (10 tool) │   │
│ qwen3.6+,  │  │  │ mcp-osint-tools  (9 tool) │   │
│ hermes-405 │  │  │ mcp-telemetry    (9 tool) │   │
│            │  │  │ mcp-browser      (9 tool) │   │
│            │  │  │ mcp-rag-engine   (7 tool) │   │
│            │  │  └──────────────────────────┘   │
└────────────┘  └─────────────────────────────────┘
```

### Model Routing

> ⚠️ Claude Code runtime'da modeli ANLIK değiştiremez — tek session = tek model.
> Model routing MCP tool katmanında çözüldü.

- **Orkestratör** (session): `qwen/qwen3-next-80b-a3b-instruct` (non-thinking,
  tool use uyumlu, `ANTHROPIC_DEFAULT_SONNET_MODEL`)
- **Derin analiz:** Claude Code `qwen_analyze()` çağırır → tool içi kod
  OpenRouter'a `qwen/qwen3.6-plus` ile ayrı istek atar
- **Exploit PoC:** Claude Code `generate_exploit_poc()` çağırır → tool içi kod
  `nousresearch/hermes-4-405b`'e istek atar
- **Paralel analiz + PoC:** `parallel_llm_analyze()` — ThreadPoolExecutor ile
  Qwen ve Hermes eş zamanlı

Tüm modeller `.env` üzerinden override edilebilir:
```
CCO_ANALYZE_MODEL=...
CCO_EXPLOIT_MODEL=...
CCO_FAST_MODEL=...
CCO_CODE_MODEL=...
```

---

## 📁 Dosya Yapısı

```
cco/
├── CLAUDE.md                    ← ANA DOSYA — hacker persona + metodoloji
├── .env.example                 ← OpenRouter config şablonu
├── .env                         ← Gerçek key (gitignore'da)
├── install-cco.sh               ← Tek komut kurulum
├── README.md
│
├── mcp-servers/                 ← 10 MCP server (181 tool)
│   ├── mcp-kali-tools/          ← 76 güvenlik aracı + LLM tools
│   ├── mcp-web-advanced/        ← 25 modern web/API saldırı aracı
│   ├── mcp-ctf-platform/        ← 14 — CTFd/HTB/THM entegrasyonu
│   ├── mcp-ad-tools/            ← 12 — Active Directory / Kerberos / SMB
│   ├── mcp-memory-server/       ← 10 — NetworkX Knowledge Graph + SQLite
│   ├── mcp-container-tools/     ← 10 — Docker/K8s container security
│   ├── mcp-osint-tools/         ← 9 — pasif OSINT + password spraying
│   ├── mcp-telemetry/           ← 9 — maliyet + call tracking
│   ├── mcp-browser/             ← 9 — Playwright client-side recon (opsiyonel)
│   └── mcp-rag-engine/          ← 7 — ChromaDB CVE/exploit/writeup search
│
├── .claude/                     ← Claude Code native konfigürasyon
│   └── skills/                  ← 19 Agent Skill (YAML frontmatter ile)
│       ├── recon-enumeration/         attack-surface-mapping/
│       ├── web-exploit/  web-advanced/  advanced-api-sec/
│       ├── binary-pwn/  crypto-forensics/  ctf-solver/
│       ├── report-generator/  source-code-review/
│       ├── active-directory/  windows-exploitation/
│       ├── post-exploitation/  stealth-evasion/  payload-generation/
│       ├── cloud-exploitation/  container-security/
│       └── mobile-security/  osint-password-spraying/
│
├── skills → .claude/skills      ← Geriye uyumluluk için symlink
│
├── workflows/                   ← Metodoloji dokümanları
│   ├── bug-bounty-workflow.md
│   ├── ctf-workflow.md
│   ├── modern-web-workflow.md
│   └── supervisor-workflow.md
│
├── rules/                       ← Güvenlik kuralları
│   ├── scope-guard.md
│   └── safety-rules.md
│
├── scripts/                     ← Yardımcılar
│   ├── attack_planner.py
│   ├── recon_daemon.py
│   ├── swarm_orchestrator.py
│   ├── budget-check.sh          ← OpenRouter bakiye sorgu
│   └── model-list.sh            ← Kullanılabilir modeller
│
└── system_prompt.md             ← (Referans — CLAUDE.md kaynağı)
```

---

## ⚙️ 10 MCP Server — 181 Tool

| Server | Tool | Öne Çıkanlar |
|--------|---|--------------|
| `kali-tools` | 76 | `nmap_scan_structured`, `sqlmap_test_structured`, `ffuf`, `nuclei`, `hydra`, `qwen_analyze`, `generate_exploit_poc`, `parallel_llm_analyze`, `swarm_dispatch`, `interactsh_*` |
| `web-advanced` | 25 | GraphQL injection, JWT attacks, OAuth/SAML, HTTP smuggling, cache poisoning, prototype pollution, WebSocket fuzz, IDOR matrix, `set_rate_limit` |
| `ctf-platform` | 14 | `ctfd_list_challenges`, `htb_submit_flag`, `thm_get_room`, decode/hash yardımcıları |
| `ad-tools` | 12 | Kerberos (AS-REP/Kerberoast), SMB enum, NTLM, BloodHound veri toplama |
| `memory-server` | 10 | `store_finding`, `store_credential`, `query_attack_paths`, `suggest_next_action` |
| `container-tools` | 10 | Container escape, K8s RBAC, secret dump, privileged pod, Helm analizi |
| `osint-tools` | 9 | `crtsh_subdomains`, `dns_recon`, `dns_zone_transfer`, `wayback_urls`, `rdap_whois`, `username_osint`, `github_code_search`, `password_spray_structured` |
| `telemetry` | 9 | `log_tool_call`, `log_llm_call`, `cost_summary`, `savings_report` |
| `browser` | 9 | `browser_screenshot`, `browser_extract_links`, `browser_security_headers`, `browser_cookie_audit`, `browser_capture_requests`, `browser_console_logs`, `browser_dom_xss_probe` (Playwright) |
| `rag-engine` | 7 | `rag_search`, `rag_add_cve`, `rag_add_writeup` (ChromaDB semantic search) |

> Not: `ad-tools`, `container-tools`, `osint-tools`, `browser` artık
> `install-cco.sh` tarafından `~/.claude.json`'a otomatik kaydedilir.
> `browser` Playwright gerektirir (opsiyonel; yoksa net hata mesajı döner).

---

## 🔧 Konfigürasyon

### `.env`
```bash
# Claude Code → OpenRouter
ANTHROPIC_AUTH_TOKEN=sk-or-v1-...
ANTHROPIC_BASE_URL=https://openrouter.ai/api
ANTHROPIC_API_KEY=                   # Boş (OAuth devre dışı)

# Alias mapping (Claude Code haiku/sonnet/opus)
ANTHROPIC_DEFAULT_SONNET_MODEL=qwen/qwen3-next-80b-a3b-instruct
ANTHROPIC_DEFAULT_HAIKU_MODEL=meta-llama/llama-3.3-70b-instruct
ANTHROPIC_DEFAULT_OPUS_MODEL=qwen/qwen3-max

# MCP tool içi modeller
CCO_ANALYZE_MODEL=qwen/qwen3.6-plus
CCO_EXPLOIT_MODEL=nousresearch/hermes-4-405b

# Bütçe
CCO_BUDGET_USD=10.00

# Veri dizini
CCO_HOME=~/.cco
```

### `~/.claude.json` (install-cco.sh tarafından oluşturulur)
10 MCP server'ın command/args/env tanımları. Mevcut dosya yedeklenir, sadece
`mcpServers` alanı güncellenir.

---

## ⚠️ Önemli Notlar

### Thinking-only modeller
`qwen/qwen3.6-plus` gibi bazı modeller **sadece `thinking` block** döndürür —
Claude Code session modeli olarak kullanırsan `result` boş görünür. Bu modelleri
sadece **MCP tool içinden** programatik olarak çağır (hali hazırda `qwen_analyze`
bu modeli kullanıyor). Session modeli olarak `qwen3-next-80b-a3b-instruct`
(non-thinking) veya `llama-3.3-70b-instruct` kullan.

### Root/sudo ortamında Claude Code
Container veya Kali root session'unda `IS_SANDBOX=1` env variable'ını set et;
aksi halde `--dangerously-skip-permissions` reddedilir.

### Bütçe ve maliyet takibi
OpenRouter her yanıtın `usage.cost` alanını döndürür. `mcp-telemetry` server
her LLM/tool çağrısını kaydeder. Session özeti için:
```
claude -p "telemetry ile bu session'daki toplam maliyeti göster"
```

---

## ⚠️ Yasal Uyarı

Bu sistem **yalnızca yasal ve etik** güvenlik testi amaçlarıyla kullanılmalıdır:

- ✅ Yazılı izin aldığınız hedefleri test edin
- ✅ Bug bounty program kurallarına uyun
- ✅ CTF yarışmalarında sportif davranın
- ✅ Zafiyetleri sorumlu şekilde raporlayın
- ❌ Yetkisiz hedeflere saldırmayın
- ❌ Bulunan verileri kötüye kullanmayın

---

*Developed for ethical security research and CTF competitions.*
*4.327 lines of Python orchestration → 0. MCP tools: 181 (10 server). Model choices: unlimited.*
