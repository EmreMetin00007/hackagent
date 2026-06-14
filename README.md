# 🔴 CCO — Claude Code Offensive Operator

> Otonom bug bounty avcısı & CTF çözücü. **Claude Code CLI** orkestrasyonu,
> **OpenRouter** üzerinden ucuz/sansürsüz modeller, **13 MCP server** ile 214
> güvenlik aracı (deterministik **validator** + **reasoning beyni** dahil). Kali Linux için.

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
- ✅ `~/.claude.json` — 13 MCP server kaydı (mevcut dosya yedeklenir)
- ✅ (opsiyonel) RAG bilgi tabanını CVE/ExploitDB/payload ile doldurma

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
> /pwn hedef.com scope: hedef.com                # Otonom recon→exploit zinciri (tek komut)
> /bugbounty hedef.com                           # Bug bounty kampanyası
> /recon-enumeration scanme.nmap.org             # Keşif skill'ini tetikle
> /web-exploit testphp.vulnweb.com/?test=query   # Web zafiyet skill'i
> /llm-security https://hedef.com/api/chat       # LLM/AI uygulama güvenliği
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
│  • ~/.claude.json → 13 MCP server kaydı     │
└──────┬──────────────┬───────────────────────┘
       │              │
       ▼              ▼
┌────────────┐  ┌─────────────────────────────────┐
│ OpenRouter │  │      MCP Server'lar (13)        │
│   API      │  │  ┌──────────────────────────┐   │
│            │  │  │ mcp-kali-tools  (76 tool) │   │
│ Session:   │  │  │ mcp-web-advanced (25 tool)│   │
│ qwen3-next │  │  │ mcp-ctf-platform (14 tool)│   │
│ 80b-a3b    │  │  │ mcp-validator   (13 tool) │   │
│            │  │  │ mcp-ad-tools    (12 tool) │   │
│ Tool içi:  │  │  │ mcp-memory-srv  (10 tool) │   │
│ qwen3.6+,  │  │  │ mcp-container   (10 tool) │   │
│ hermes-405 │  │  │ mcp-osint-tools  (9 tool) │   │
│            │  │  │ mcp-telemetry    (9 tool) │   │
│            │  │  │ mcp-browser      (9 tool) │   │
│            │  │  │ mcp-reasoning   (14 tool) │   │
│            │  │  │ mcp-rag-engine   (7 tool) │   │
│            │  │  │ mcp-llm-security (6 tool) │   │
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
├── mcp-servers/                 ← 13 MCP server (214 tool)
│   ├── mcp-kali-tools/          ← 76 güvenlik aracı + LLM tools
│   ├── mcp-web-advanced/        ← 25 modern web/API saldırı aracı
│   ├── mcp-ctf-platform/        ← 14 — CTFd/HTB/THM entegrasyonu
│   ├── mcp-validator/           ← 13 — DETERMİNİSTİK exploit doğrulama (XBOW-tarzı)
│   ├── mcp-ad-tools/            ← 12 — Active Directory / Kerberos / SMB
│   ├── mcp-memory-server/       ← 10 — NetworkX Knowledge Graph + SQLite
│   ├── mcp-container-tools/     ← 10 — Docker/K8s container security
│   ├── mcp-osint-tools/         ← 9 — pasif OSINT + password spraying
│   ├── mcp-telemetry/           ← 9 — maliyet + call tracking
│   ├── mcp-browser/             ← 9 — Playwright client-side recon (opsiyonel)
│   ├── mcp-reasoning/           ← 14 — BEYİN: deep_think (recon→zincir→doğrula→skorla) + plan + Reflexion + öğrenme + kill-chain + payload-evo + exploitability + skill-router
│   ├── mcp-rag-engine/          ← 7 — ChromaDB CVE/exploit/writeup search
│   └── mcp-llm-security/        ← 6 — OWASP LLM Top 10 (prompt inj./jailbreak)
│
├── .claude/                     ← Claude Code native konfigürasyon
│   ├── commands/                ← Custom slash command'lar
│   │   ├── pwn.md               ←   /pwn <hedef> — otonom recon→exploit zinciri
│   │   └── bugbounty.md         ←   /bugbounty <hedef> — bug bounty kampanyası
│   └── skills/                  ← 22 Agent Skill (YAML frontmatter ile)
│       ├── recon-enumeration/  attack-surface-mapping/  llm-security/
│       ├── web-exploit/  web-advanced/  advanced-api-sec/
│       ├── exploit-validation/ ← deterministik doğrulama metodolojisi
│       ├── deep-reasoning/     ← derin düşünme: plan + reflexion + öğrenme (beyin)
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
│   ├── recon-to-exploit-workflow.md ← /pwn'in otonom zinciri
│   ├── bug-bounty-workflow.md
│   ├── ctf-workflow.md
│   ├── modern-web-workflow.md
│   ├── benchmark-workflow.md    ← CCO'yu XBOW benchmark'ına karşı çalıştır
│   └── supervisor-workflow.md
│
├── rules/                       ← Güvenlik kuralları
│   ├── scope-guard.md
│   └── safety-rules.md
│
├── tests/                       ← pytest smoke/regresyon suite
│   ├── conftest.py
│   ├── test_mcp_servers.py      ← 13 server import + 214 tool sayım guard
│   ├── test_validator.py        ← deterministik validator oracle testleri
│   ├── test_reasoning.py        ← reasoning beyni (EV/öğrenme/plan) testleri
│   └── test_xbow_benchmark.py   ← benchmark harness (mock) testleri
│
├── scripts/                     ← Yardımcılar
│   ├── cco-profile.sh           ← MCP profil değiştir (TOKEN TASARRUFU)
│   ├── token-estimate.py        ← Profil token maliyeti tablosu
│   ├── xbow_benchmark.py        ← XBOW 104-challenge benchmark harness
│   ├── xbow_bench_fixtures/     ← offline mock benchmark seti (harness testi)
│   ├── rag-bootstrap.py/.sh     ← RAG bilgi tabanı doldurma
│   ├── recon_daemon.py          ← (kali-tools'a wired)
│   ├── swarm_orchestrator.py    ← (kali-tools'a wired)
│   ├── attack_planner.py        ← (standalone CLI — orphan, opsiyonel)
│   ├── budget-check.sh          ← OpenRouter bakiye sorgu
│   └── model-list.sh            ← Kullanılabilir modeller
│
└── system_prompt.md             ← (Referans — CLAUDE.md kaynağı)
```

---

## ⚙️ 13 MCP Server — 214 Tool

| Server | Tool | Öne Çıkanlar |
|--------|---|--------------|
| `kali-tools` | 76 | `nmap_scan_structured`, `sqlmap_test_structured`, `ffuf`, `nuclei`, `hydra`, `qwen_analyze`, `generate_exploit_poc`, `parallel_llm_analyze`, `swarm_dispatch`, `interactsh_*` |
| `web-advanced` | 25 | GraphQL injection, JWT attacks, OAuth/SAML, HTTP smuggling, cache poisoning, prototype pollution, WebSocket fuzz, IDOR matrix, `generate_stealth_curl` |
| `ctf-platform` | 14 | `ctfd_list_challenges`, `htb_submit_flag`, `thm_get_room`, decode/hash yardımcıları |
| `validator` 🆕 | 13 | **Deterministik exploit doğrulama (XBOW-tarzı):** `validate_sqli` (differential boolean), `validate_ssti` (aritmetik oracle), `validate_command_injection` (echo+timing), `validate_path_traversal`, `validate_xss_reflection`, `validate_open_redirect`, `validate_ssrf_oob`+`confirm_oob_callback` (OOB), `validate_xxe`, `validate_auth_bypass`, `validate_idor`, `validate_finding`, `generate_validation_report` |
| `ad-tools` | 12 | Kerberos (AS-REP/Kerberoast), SMB enum, NTLM, BloodHound veri toplama |
| `memory-server` | 10 | `store_finding`, `store_credential`, `query_attack_paths`, `suggest_next_action` |
| `container-tools` | 10 | Container escape, K8s RBAC, secret dump, privileged pod, Helm analizi |
| `osint-tools` | 9 | `crtsh_subdomains`, `dns_recon`, `dns_zone_transfer`, `wayback_urls`, `rdap_whois`, `username_osint`, `github_code_search`, `password_spray_structured` |
| `telemetry` | 9 | `log_tool_call`, `log_llm_call`, `get_cost_summary`, `get_savings_report`, `get_metrics_dashboard` |
| `browser` | 9 | `browser_screenshot`, `browser_extract_links`, `browser_security_headers`, `browser_cookie_audit`, `browser_capture_requests`, `browser_console_logs`, `browser_dom_xss_probe` (Playwright) |
| `reasoning` 🆕 | 14 | **Biliş/beyin katmanı (DeepSeek-destekli):** `deep_think` (bayrak gemisi — recon→zincir→doğrula→skorla orkestratörü), `plan_attack_tree` (Bayesçi EV + ToT), `next_best_action`, `reason_reflexion` (actor↔critic self-correct), `critic_review`, `record_lesson`, `recall_lessons`, `lesson_stats` (kalıcı öğrenme) · **Kill-Chain:** `compose_attack_chains` (çok-adımlı zincir), `kill_chain_report` · **Payload Evo:** `evolve_payload` (WAF-aware), `record_payload_result` · **Kalibre güven:** `exploitability_score` · **Skill Router:** `recommend_skills` (fingerprint→/skill) |
| `rag-engine` | 7 | `rag_search`, `rag_similar_exploits`, `rag_ingest_cve`, `rag_ingest_exploitdb`, `rag_ingest_writeup`, `rag_bulk_ingest`, `rag_stats` (ChromaDB) |
| `llm-security` | 6 | `llm_prompt_injection_probe`, `llm_system_prompt_leak`, `llm_jailbreak_test`, `llm_data_leak_probe`, `generate_injection_payloads`, `llm_owasp_top10_checklist` (OWASP LLM Top 10) |

> Not: 13 server'ın tamamı `install-cco.sh` tarafından `~/.claude.json`'a
> otomatik kaydedilir. `browser` Playwright gerektirir (opsiyonel; yoksa net
> hata mesajı döner). `rag-engine` ilk kullanımda boştur — install sırasında
> (veya `python3 scripts/rag-bootstrap.py` ile) CVE/ExploitDB/payload ile doldurulur.

---

## 🧠 Reasoning Beyni — Güçlü LLM Çekirdeği 🆕

CCO'nun zekası tek bir session modelinden ibaret değil. `mcp-reasoning` server'ı
ajana gerçek bir **biliş katmanı** ekler — üç pilar birbirini besler:

| Pilar | Ne yapar | Tool'lar |
|---|---|---|
| **1a Reflexion** | actor→critic→(validator)→retry: kendi exploit'ini eleştirir, başarısızsa öğrenip revize eder → halüsinasyonsuz | `reason_reflexion`, `critic_review` |
| **1d Bayesçi planlama** | knowledge-graph'i okur, her vektörü beklenen-değer (EV) ile puanlar, tree-of-thought zinciri kurar | `plan_attack_tree`, `next_best_action` |
| **1e Kalıcı öğrenme** | "neyin işe yaradığı" derslerini saklar; öğrenilen win-rate'ler planlayıcının önceliklerine karışır → **zamanla akıllanır** | `record_lesson`, `recall_lessons`, `lesson_stats` |

**Bayrak gemisi — tek çağrı:**
```
mcp__reasoning__deep_think(task, target, scope, context)
  → recall_lessons (geçmiş deneyim) + plan_attack_tree (Bayesçi EV) + reason_reflexion (self-correct)
  → chosen_action.validate_with ile DOĞRULA → exploit → record_lesson
```

**Altın döngü (beynin akıllanması):**
```
deep_think → validator (deterministik) → exploit → record_lesson(worked=?)
     ▲                                                        │
     └──────── öğrenilen win-rate → EV priors'ı günceller ◄───┘
```

Modeller env ile güçlendirilebilir (LLM yoksa EV/öğrenme yine çalışır):
```
# DeepSeek (önerilen güçlü reasoning) — anahtar varsa beyin OTOMATİK DeepSeek'e geçer:
export DEEPSEEK_API_KEY=sk-...        # actor=deepseek-reasoner, critic=deepseek-chat
# veya ~/.cco/config.yaml →  llm:\n  deepseek_api_key: sk-...

# Override (opsiyonel):
CCO_REASON_MODEL=deepseek-reasoner    # actor/planner (DeepSeek varsayılanı)
CCO_CRITIC_MODEL=deepseek-chat        # critic (actor'dan farklı = daha sert eleştiri)
# DeepSeek yoksa OpenRouter'a düşer: qwen/qwen3.6-plus + nousresearch/hermes-4-405b
# Daha üst seviye için CCO_REASON_MODEL=deepseek-v4-pro (thinking) da kullanılabilir
```
> ⚠️ API anahtarını **asla** koda/commit'e koyma — yalnızca env veya `~/.cco/config.yaml`.
Detay: skill `deep-reasoning`.

---

## 🧪 Deterministik Validator (XBOW-tarzı) + Benchmark 🆕

CCO'nun XBOW'a karşı en büyük açığı **deterministik doğrulama** ve **bağımsız
kıyas kanıtıydı**. v3.2 bunu iki parçayla kapatır:

**1) `mcp-validator` — "yaratıcı AI keşfeder, mantık doğrular".** Bir bulgunun
*gerçekten* exploit edilebilir olduğunu LLM görüşü değil, **nesnel oracle'larla**
kanıtlar (differential boolean SQLi, aritmetik SSTI, echo-token/timing cmdi,
dosya-imzası LFI/XXE, OOB korelasyonu SSRF, Location-header open redirect...).
Her doğrulama `~/.cco/validations/` altına **reproducible audit-trail** olarak yazılır.

```
# Recon/exploit sırasında bir şüphe → doğrula → CONFIRMED ise raporla
mcp__validator__validate_sqli(target_url="http://t/item?id=1", param="id")
mcp__validator__validate_finding(vuln_type="ssti", target_url=..., params_json='{"param":"name"}')
mcp__validator__generate_validation_report(result_json=...)   # XBOW-tarzı PoC raporu
```

**2) XBOW Benchmark Harness** — CCO'yu XBOW'un 104-challenge public benchmark'ına
karşı çalıştırıp skorlar (başarı = gerçek flag, yalnızca "tespit" değil):

```bash
python3 scripts/xbow_benchmark.py list  --mock              # gömülü mock seti (offline)
python3 scripts/xbow_benchmark.py run   --all --mock        # harness mantığı testi (SELF-TEST)
python3 scripts/xbow_benchmark.py list  --repo ~/xbow-benchmarks   # gerçek 104 challenge
python3 scripts/xbow_benchmark.py run   --all --repo ~/xbow-benchmarks --timeout 1200 \
    --resume --max-cost 30 --junit ~/.cco/benchmark/junit.xml      # resume+bütçe+CI export
python3 scripts/xbow_benchmark.py score                     # kategori/level scorecard + XBOW kıyas
```

**v1.1 kanıt bütünlüğü:** harness artık (1) **anti-cheat echo guard** (flag
prompt'taysa SOLVED sayılmaz), (2) **validator-onaylı çözüm** metriği (oracle
kanıtı vs LLM iddiası), (3) **reprodüksiyon metadata** (mode/model/git_commit/host)
+ per-challenge transcript, (4) mock scorecard'a **"SELF-TEST — kanıt değil"
watermark**'ı (mock skoru XBOW ile kıyaslanmaz). Yayınlanabilir kanıt = `--repo`
(docker) koşusu.

Detaylı metodoloji: `workflows/benchmark-workflow.md`.

---

## 💸 Token Tasarrufu — MCP Profilleri

Claude Code **her istekte tüm kayıtlı MCP server'ların tool şemalarını** context'e
yükler — 13 server / 214 tool ≈ **~32K token/istek** (sadece şema). Göreve göre
yalnızca ilgili server'ları yükleyerek istek başına 10-24K token tasarruf edilir.

```bash
bash scripts/cco-profile.sh list      # profilleri + tahmini maliyeti gör
bash scripts/cco-profile.sh llm       # sadece LLM-sec görevine geç (~8K, %74↓)
bash scripts/cco-profile.sh web       # web + validator + reasoning görevi (~25K, %20↓)
bash scripts/cco-profile.sh full      # 13 server (varsayılan)
python3 scripts/token-estimate.py     # server + profil token tablosu
python3 scripts/token-estimate.py --current   # aktif profilin maliyeti
```

| Profil | Server | Tool | ~token/istek | Tasarruf |
|--------|---|---|---|---|
| `llm`   | 5 | 59 | ~8.2K  | **%74** |
| `min`   | 4 | 103 | ~16.2K | %49 |
| `recon` | 6 | 121 | ~18.9K | %41 |
| `ad`    | 6 | 125 | ~19.7K | %38 |
| `ctf`   | 7 | 137 | ~21.5K | %33 |
| `web`   | 9 | 163 | ~25.4K | %20 |
| `full`  | 13 | 214 | ~32.0K | %0 |

> Profil değişikliği **yeni bir `claude` oturumunda** etkili olur. Mevcut config
> (doldurulmuş token'lar dahil) korunur; yalnızca `mcpServers` alanı güncellenir.
> Uzun oturumlarda ek tasarruf için Claude Code'un `/compact` komutunu kullan.

---

## 🧪 Test (regresyon)

```bash
pip install pytest
pytest -q                    # 12 server import + 200 tool sayım guard'ı + validator + benchmark
```

`tests/test_mcp_servers.py` her server'ı import eder, tool sayısını doğrular
(yeni tool eklerken `EXPECTED_TOOL_COUNTS` güncellenmeli) ve metadata + pure-function
temel çağrılarını test eder. `tests/test_validator.py` deterministik oracle'ları,
`tests/test_reasoning.py` reasoning beynini (EV/öğrenme/plan), `tests/test_xbow_benchmark.py`
benchmark harness'ını (mock) doğrular. Tamamen offline çalışır.

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
13 MCP server'ın command/args/env tanımları. Mevcut dosya yedeklenir, sadece
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
*4.327 lines of Python orchestration → 0. MCP tools: 214 (13 server; deterministik validator + reasoning beyni dahil). Skills: 22. XBOW benchmark harness dahil. Model choices: unlimited.*
