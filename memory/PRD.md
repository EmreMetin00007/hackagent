# CCO — Claude Code Offensive Operator

## Original Problem Statement
AgentCracker v3.1'in (4.327 satır Python orkestrasyon kodu ile) Claude Code CLI +
OpenRouter mimarisine migrasyonu. Hedef: silinen 4.300+ satır Python kod, korunan
6 MCP server (139+ tool), 7 skill, 4 workflow, 2 rules; eklenen `CLAUDE.md`, `.env`,
`~/.claude.json`, `install-cco.sh`. Platform: Kali Linux CLI. LLM: OpenRouter
(`ANTHROPIC_BASE_URL` override ile Qwen 3 / Hermes 4 / Llama 3.3).

## Architecture
- **Orkestratör:** Claude Code CLI v2.1.118 (npm global)
- **LLM transport:** `ANTHROPIC_BASE_URL=https://openrouter.ai/api` + `ANTHROPIC_AUTH_TOKEN`
- **Session modeli:** `qwen/qwen3-next-80b-a3b-instruct` (non-thinking, tool use uyumlu,
  alias `sonnet`). Thinking-only modeller (`qwen/qwen3.6-plus`) session modeli olarak
  çalışmaz (boş result döndürür); sadece MCP tool içinden programatik çağrıda kullanılır.
- **11 MCP server** stdio transport ile subprocess olarak başlatılır (187 tool)
- **Model delegation:** CLAUDE.md'de kurallar yazılı; Claude Code doğru tool'u seçer,
  tool'lar `os.environ.get("CCO_ANALYZE_MODEL", ...)` ile OpenRouter'a istek atar
- **Veri:** `~/.cco/` altında SQLite (memory), ChromaDB (rag), logs, approvals

## User Personas
- **Pentester / Bug bounty hunter:** `source .env && claude` → Recon'dan rapora
  uzanan otonom saldırı zinciri
- **CTF solver:** Web/Pwn/Crypto/Forensics challenge'ları Kali araçları + LLM
  analizi ile çözer
- **Security researcher:** Hermes 405B ile özel PoC üretimi, sansürsüz analiz

## Core Requirements (Static)
1. Python orkestrasyon kodunun tamamı silinmeli (PRD §9)
2. MCP server'lar Claude Code tarafından keşfedilebilir ve çağrılabilir olmalı
3. OpenRouter üzerinden çalışan modeller session modeli olarak tool use desteklemeli
4. Model routing MCP tool içinde yapılmalı (session içinde model değişmez)
5. CLAUDE.md @reference syntax ile skills/workflows/rules lazy-load etmeli
6. `install-cco.sh` tek komutla Kali'de kurulumu tamamlamalı
7. Scope enforcement + budget tracking (telemetry MCP) aktif olmalı

## What's Been Implemented
### 2026-06-14 — Reasoning Beyni: güçlü LLM çekirdeği (Reflexion + Bayesçi plan + öğrenme)

**Kullanıcı seçimi:** 1a (Reflexion) + 1d (saldırı planlama motoru) + 1e (kalıcı öğrenme),
tam otonomi önceliği. Amaç: ajanın "düşünme" gücünü tek session modelinden çok-pilarlı
bir biliş katmanına taşımak.

**Yeni `mcp-reasoning` (13. server, 8 tool) — üç pilar birbirini besler:**
- **1a Reflexion:** `reason_reflexion` (actor→critic→retry; actor=CCO_REASON_MODEL,
  critic=CCO_CRITIC_MODEL farklı → daha sert eleştiri), `critic_review`. Halüsinasyonu
  düşürür; onaydan sonra validator'a bağlanır.
- **1d Bayesçi planlama:** `plan_attack_tree` (memory'deki findings/endpoints'i okur,
  her vektörü EV = blended_prob × impact × (1−0.4·effort) ile puanlar + LLM varsa
  tree-of-thought zinciri), `next_best_action` (tek en yüksek-EV aksiyon, deterministik).
  Her aksiyon `validate_with` (validator) + `recommended_tool` ile döner.
- **1e Kalıcı öğrenme:** `record_lesson`/`recall_lessons`/`lesson_stats` (`~/.cco/lessons.db`).
  Öğrenilen win-rate'ler `_blended_prob` ile planlayıcının Bayesçi önceliklerine
  pseudo-count'lu karışır → **altın döngü:** deep_think→validate→exploit→record_lesson→
  priors güncellenir → zamanla akıllanır.
- **⚡ `deep_think` (bayrak gemisi):** recall_lessons + plan_attack_tree + reason_reflexion'ı
  tek çağrıda birleştirir; deneyimle beslenmiş, kendini-eleştirmiş, validator-bağlı
  aksiyon planı döndürür.

**Tasarım notları:** LLM yoksa EV/öğrenme/plan tamamen offline çalışır (graceful).
Modeller env ile güçlendirilebilir (CCO_REASON_MODEL/CCO_CRITIC_MODEL; OpenRouter'da
gpt-oss-120b/deepseek-v4'e override edilebilir — web araştırmasıyla önerildi).
Endpoint-hint çıkarımı RCE'yi spekülatif üretmeyecek şekilde sıkılaştırıldı.

**Entegrasyon:** CLAUDE.md **Kural 6 (önce deep_think)** + öncelik sırası adım 3 + ekosistem
tablosu. Yeni skill `deep-reasoning` (22. skill). Profillere reasoning eklendi (min/recon/
web/ctf/ad/full). cco-profile.sh, token-estimate.py, install-cco.sh, README güncellendi →
**12→13 server, 200→208 tool, 21→22 skill.**

**Doğrulama:** ✅ `pytest -q` → **65 passed, 1 skipped** (test_reasoning: EV sıralaması,
öğrenme döngüsünün prior'ı güncellemesi, recall relevance, deep_think offline pilar birleşimi,
reflexion graceful-without-key). ✅ Offline deep_think demo: SSTI/SQLi/login seed → EV ile
sıraladı, sql_injection seçti, `validate_sqli` hook'una bağladı.


### 2026-06-14 — Deterministik Validator (XBOW-tarzı) + XBOW Benchmark Harness

**Tetik:** Kullanıcı CCO'yu XBOW ile kıyasladı. İki en büyük açık tespit edildi:
(1) deterministik exploit doğrulama yok, (2) bağımsız/kıyaslanabilir benchmark kanıtı
yok. Kullanıcı her ikisini de eklemeyi istedi.

**1. `mcp-validator` (yeni 12. server, 13 tool) — "yaratıcı AI keşfeder, mantık doğrular":**
- Bir bulgunun GERÇEKTEN exploit edilebilir olduğunu LLM görüşü değil, nesnel
  oracle'larla deterministik kanıtlar. Tool'lar: `validate_sqli` (differential
  boolean + error + time), `validate_ssti` (rastgele a*b aritmetik oracle),
  `validate_command_injection` (echo-token + statistical timing), `validate_path_traversal`
  + `validate_xxe` (/etc/passwd & win.ini içerik imzası), `validate_xss_reflection`
  (kaçışsız yansıma; execution→browser_dom_xss), `validate_open_redirect` (Location host),
  `validate_ssrf_oob` + `confirm_oob_callback` (interactsh OOB token korelasyonu),
  `validate_auth_bypass` + `validate_idor` (differential), `validate_finding` (dispatcher),
  `generate_validation_report` (XBOW-tarzı Markdown PoC kanıt raporu).
- Confidence oracle gücüne göre deterministik atanır (oob 0.99 → unescaped_reflection 0.75).
  Her doğrulama `~/.cco/validations/` altına reproducible audit-trail olarak yazılır.
- CLAUDE.md'ye **Kural 5 (exploit doğrulama / false-positive guard)** + kill-chain
  faz 3.5 + öncelik sırası adım 7 eklendi. Yeni skill `exploit-validation` (21. skill).

**2. XBOW Benchmark Harness (`scripts/xbow_benchmark.py`):**
- CCO'yu XBOW'un 104-challenge public benchmark'ına (github.com/xbow-engineering/
  validation-benchmarks) karşı çalıştırır; başarı = gerçek flag (yalnızca tespit değil).
- Subcommand'lar: `list / run / score / up / down`. Pluggable Runtime (DockerRuntime |
  MockRuntime) + Solver (CCOSolver `claude -p` | MockSolver). Flag oracle (regex),
  kategori/level pass-rate, maliyet/süre, XBOW & arXiv:2508.20816 referans kıyası,
  Markdown scorecard (`~/.cco/benchmark/scorecard.md`).
- Offline `--mock` modu + 4 gömülü fixture (`scripts/xbow_bench_fixtures/`, 3 solvable/
  1 negatif) → harness uçtan uca doğrulanabilir. Metodoloji: `workflows/benchmark-workflow.md`.

**Profiller/sayımlar:** `web` ve `ctf` profillerine + `full`'a validator eklendi.
cco-profile.sh, token-estimate.py, install-cco.sh (~/.claude.json kaydı + import loop),
README, CLAUDE.md güncellendi → **11→12 server, 187→200 tool, 20→21 skill, 4→5 workflow**.

**Doğrulama:** ✅ `pytest -q` → **53 passed, 1 skipped** (test_mcp_servers 200-tool guard,
test_validator 7 oracle/dispatcher/report testi, test_xbow_benchmark 6 harness testi).
✅ `xbow_benchmark.py run --all --mock` → 3/4 (%75) doğru skorladı. ✅ validator 13 tool
listeleniyor, FastMCP import temiz.



### 2026-01-24 — pytest Smoke Suite + Token Tasarrufu (MCP Profilleri)

**1. pytest regresyon suite (`tests/`):**
- `test_mcp_servers.py` + `conftest.py`: 11 server import + `list_tools` + beklenen
  tool sayısı guard'ı (`EXPECTED_TOOL_COUNTS`, toplam 187) + metadata + offline
  pure-function temel çağrıları (llm-security payload/checklist, browser graceful).
- İzole `CCO_HOME` (geçici dizin), tamamen offline. ✅ **38 passed, 1 skipped** (2.1s).
- Yeni tool eklerken sayım tutmazsa test kasıtlı kırılır → regresyon yakalanır.

**2. Token tasarrufu — MCP Profil sistemi (ölçülen sorun: ~28K token/istek):**
- Tespit: Claude Code her istekte 11 server / 187 tool şemasını context'e yüklüyor
  → ~27.769 token/istek (kali-tools tek başına %44). + CLAUDE.md ~5.6K.
- `scripts/cco-profile.sh <profil>`: `~/.claude.json` mcpServers'ı göreve göre
  alt kümeye indirir (min/recon/web/llm/ctf/ad/full). Mevcut config + doldurulmuş
  token'lar korunur; backup alınır.
- `scripts/token-estimate.py`: server + profil bazında token maliyeti tablosu;
  `--current` ile aktif profil maliyeti.
- ✅ Doğrulandı: `llm` profili 28K→**~8.2K (%71↓)**, `recon` ~17.4K (%37↓),
  `ctf`/`ad`/`web` %24-38↓. Profil değişimi + diğer config key korunumu test edildi.
- CLAUDE.md bütçe kuralına profil önerisi eklendi; install-cco.sh çıktısına ipucu.

**Doküman:** README'ye "Token Tasarrufu — MCP Profilleri" + "Test" bölümleri,
dosya yapısı (tests/, yeni scriptler) güncellendi.

### 2026-01-24 — LLM Security + RAG Bootstrap + Custom Commands + Tech Debt

Kullanıcı seçimi: #1 (RAG bootstrap), #2 (AI/LLM security), #3 (custom commands),
#8 (teknik borç). 4 başlık da tamamlandı.

**#1 — RAG bootstrap wiring (atıl alt sistemi aktive etti):**
- `rag-engine` (7 tool) boş başlıyordu; `scripts/rag-bootstrap.py` (488 satır,
  NVD CVE + ExploitDB + PayloadsAllTheThings ingester) yazılmış ama hiç çağrılmıyordu.
- `install-cco.sh`'a PHASE 8 eklendi: opsiyonel RAG bootstrap (`CCO_RAG_BOOTSTRAP=1`
  ile otomatik veya interaktif y/N; network'te asmamak için default skip).
- ✅ Doğrulandı: path eşleşiyor (`CCO_HOME/rag_db`), `--dry-run` NVD'ye erişti
  (354K CVE), `--seed-only` 13 CVE yazdı, `rag-engine.rag_search` AYNI DB'den
  semantic search ile okudu (relevance skorlu) — uçtan uca çalışıyor.

**#2 — AI/LLM Güvenliği (yeni domain, sette hiç yoktu):**
- Yeni server `mcp-llm-security` (6 tool): `llm_prompt_injection_probe` (LLM01),
  `llm_system_prompt_leak` (LLM07), `llm_jailbreak_test`, `llm_data_leak_probe`
  (LLM02), `generate_injection_payloads`, `llm_owasp_top10_checklist`.
- Hedef LLM endpoint'ine HTTP probe atar (`{{PROMPT}}` body template); kendi
  tarafımızda LLM key gerekmez. Zararsız canary/sentinel kullanır.
- Yeni skill `llm-security` (OWASP LLM Top 10 2025 metodolojisi).
- ✅ Doğrulandı: zafiyetli mock'ta injection 6/6, leak 6, jailbreak 5/5 tespit;
  güvenli mock'ta 0 false-positive.

**#3 — Custom slash command'lar (`.claude/commands/` ilk kez):**
- `/pwn <hedef>` → recon-to-exploit-workflow'u otonom yürütür (attack-surface →
  recon → exploit → rapor; scope + approval kullanıcıda).
- `/bugbounty <hedef>` → bug-bounty-workflow (OPSEC + ödül optimizasyonu).
- Format: `.claude/commands/<isim>.md` + `$ARGUMENTS` (web ile teyit edildi).

**#8 — Teknik borç:**
- Eksik `requirements.txt` eklendi: `mcp-ad-tools`, `mcp-osint-tools`
  (`mcp-container-tools`'da zaten vardı).
- `attack_planner.py` durumu netleşti: **orphan** (307 satır, hiçbir yerden
  çağrılmıyor; memory-server'ın `query_attack_paths`/`suggest_next_action` graph
  motoruyla fonksiyonel olarak çakışıyor). Standalone analiz CLI'si olarak
  bırakıldı — silinmedi; PRD'de durumu belgelendi. (`recon_daemon.py` ve
  `swarm_orchestrator.py` ise kali-tools'a wired ✅.)

**Doküman senkronu:** README, CLAUDE.md, system_prompt.md → 11 server / 187 tool /
20 skill / 2 command. install-cco.sh → llm-security kaydı + import loop + RAG fazı.

**Toplam:** 10→11 server, 181→187 tool, 19→20 skill, 0→2 custom command.

### 2026-01-24 — Recon→Exploit Zincir Workflow + set_rate_limit Düzeltmesi

**1. Yeni workflow:** `workflows/recon-to-exploit-workflow.md` — pasif keşiften
  (attack-surface-mapping) aktif keşfe (recon-enumeration) ve exploit'e
  (web-exploit/web-advanced) otomatik zincir. Köprü = `memory-server` Knowledge
  Graph (her faz `store_*` yazar, sonraki faz `query_attack_paths`/
  `suggest_next_action` okur). 6 faz + akış şeması + sürekli döngü kuralı.
  CLAUDE.md workflow tablosuna kaydedildi.
- ✅ Workflow'daki 34 `mcp__*` tool referansının tamamı gerçek inventory ile
  doğrulandı (0 hayalî tool).

**2. `set_rate_limit` doküman hatası düzeltildi:** Bu tool gerçekte hiçbir
  server'da YOK ama README/CLAUDE.md/system_prompt.md/modern-web-workflow.md/
  stealth-evasion'da referans veriliyordu. Gerçek OPSEC tool'larıyla
  değiştirildi: `generate_stealth_curl` + `api_rate_bypass_probe` (web-advanced).
  Tüm 5 dosyadaki referanslar temizlendi.

**3. Telemetry tool adı düzeltmesi:** `cost_summary`/`savings_report` →
  gerçek adlar `get_cost_summary`/`get_savings_report`/`get_metrics_dashboard`
  (README, CLAUDE.md, workflow).

### 2026-01-24 — Doküman Senkronu + osint/browser MCP Genişletme

**Tetik:** Doküman-kod tutarsızlığı tespit edildi — README/CLAUDE.md "6 server,
139+ tool, 7 skill" diyordu; gerçekte 10 server / 168 tool / 18 skill vardı.

**1. MCP Tool Genişletme (#2 — osint-tools 2→9, browser 3→9):**
- `mcp-osint-tools` (+7 yeni tool): `crtsh_subdomains` (CT log subdomain),
  `dns_recon` (A/AAAA/MX/NS/TXT/CNAME/SOA + SPF/DMARC), `dns_zone_transfer`
  (AXFR), `wayback_urls` (archive.org CDX), `rdap_whois` (API key'siz WHOIS),
  `username_osint` (14 platform sherlock-tarzı), `github_code_search`
  (GITHUB_TOKEN ile kod / token'sız repo araması)
- `mcp-browser` (+6 yeni tool): `browser_extract_links` (saldırı yüzeyi),
  `browser_security_headers` (CSP/HSTS/XFO), `browser_cookie_audit`
  (HttpOnly/Secure/SameSite), `browser_capture_requests` (gizli API endpoint),
  `browser_console_logs` (JS leak), `browser_dom_xss_probe` (canary reflection)
- `mcp-osint-tools/requirements.txt` eklendi (mcp, requests, dnspython)

**2. Yeni Skill (#2a):** `attack-surface-mapping` — pasif OSINT + client-side
  recon metodolojisi; osint-tools + browser tool'larını 4 fazda zincirler
  (DNS/CT → Wayback/GitHub → client-side → güvenlik konfig denetimi).
  Toplam skill: 18 → 19.

**3. Doküman Senkronu (#1c):**
- `README.md`: 6→10 server, 139+→181 tool, 7→19 skill, mimari diyagramı,
  dosya yapısı, server tablosu güncellendi
- `CLAUDE.md`: MCP ekosistem tablosu (10 server/181 tool), Kural 1 skill listesi
  (19 skill), protokol skill tetikleyici tablosu (19 satır)
- `system_prompt.md`: MCP ekosistem tablosu 10 server'a güncellendi
- `install-cco.sh`: kayıtsız 4 server (`ad-tools`, `container-tools`,
  `osint-tools`, `browser`) `~/.claude.json` mcpServers'a eklendi; import test
  loop'u 10 server'a genişletildi; sayaç mesajları güncellendi

**Doğrulama:**
- ✅ 10/10 server import OK (`mcp` paketi kuruldu)
- ✅ `ruff check` — All checks passed (osint-tools, browser)
- ✅ Fonksiyonel: `dns_recon`, `rdap_whois`, `username_osint` (8 platform) gerçek
  veriyle çalıştı; `crtsh_subdomains`/`wayback_urls` graceful error handling
  doğrulandı (crt.sh 502 / archive.org timeout — dış servis, kod doğru)
- ✅ `browser` Playwright yoksa net hata mesajı döndürüyor (gated import)
- ⚠️ Browser tool'larının canlı testi Playwright+chromium kurulumu gerektirir
  (gerçek Kali'de `playwright install chromium` ile çalışır)

### 2026-01-23 — Migration MVP (Faz 0 → 3 tümü tek oturumda)
- **Faz 0 — Test & Temizlik** (✅ TAMAMLANDI)
  - Claude Code CLI v2.1.118 npm ile kuruldu
  - OpenRouter Text + Tool use uyum testi: `qwen/qwen3-next-80b-a3b-instruct`,
    `meta-llama/llama-3.3-70b-instruct` session modeli olarak çalışıyor
  - `qwen/qwen3.6-plus` thinking-only → sadece MCP tool içinde kullanılacak
  - **4.327 satır Python silindi:** `hackeragent/`, `pyproject.toml`,
    `requirements.txt`, `config.yaml`, `.github/`, `memory/`, `install.sh`, `.emergent/`

- **Faz 1 — MCP Entegrasyonu** (✅ TAMAMLANDI)
  - Tüm MCP server'larda `HACKERAGENT_HOME` → `CCO_HOME` rename
  - `~/.hackeragent` default → `~/.cco` değişti
  - `keyring.get_password("hackeragent")` → `keyring.get_password("cco")`
  - HTTP-Referer `hackeragent.local` → `cco.local`
  - `qwen_analyze`, `generate_exploit_poc`, `parallel_llm_analyze` tool'ları
    hardcoded model yerine `CCO_ANALYZE_MODEL` / `CCO_EXPLOIT_MODEL` env okuyor
  - `get_api_key_secure()` hem `OPENROUTER_API_KEY` hem `ANTHROPIC_AUTH_TOKEN` okuyor
  - Python bağımlılıkları: `mcp[cli]`, `chromadb`, `networkx`, `pycryptodome`,
    `PyYAML`, `beautifulsoup4`, `dnspython`, `aiohttp`, `requests` (+fastmcp)
  - 6 MCP server import testi ✅ (kali-tools, memory-server, telemetry, rag-engine,
    ctf-platform, web-advanced)
  - `ruff check mcp-servers/` — All checks passed

- **Faz 2 — CLAUDE.md + Config** (✅ TAMAMLANDI)
  - `CLAUDE.md` yazıldı (12.6KB): CCO header + MCP tool ekosistemi +
    model delegation kuralları + OODA + Kill Chain + CTF metodoloji +
    Phase 7 (OOB/browser/JS) + `@rules/` `@skills/` `@workflows/` lazy-load
  - `.env` (gerçek key ile) + `.env.example`
  - `install-cco.sh` (13.2KB, 7 faz: Kali araçları → Python deps → veri dizini
    → Claude Code → .env setup → ~/.claude.json MCP kayıt → doğrulama)
  - `~/.claude.json` — 6 MCP server CCO_HOME env ile kayıtlı
  - `README.md` v2.0 için yeniden yazıldı
  - `.gitignore` CCO için güncellendi (.env, ~/.cco, .claude.json* hariç tutuldu)
  - `scripts/budget-check.sh` (OpenRouter credits)
  - `scripts/model-list.sh` (filtreli model listesi)

- **Faz 3 — E2E Doğrulama** (✅ TAMAMLANDI, container'da)
  - ✅ `claude -p "Which MCP servers..."` → 6 server listeleyor: ctf-platform,
    kali-tools, memory-server, rag-engine, telemetry, web-advanced
  - ✅ `store_finding(target='test-target.lab', vulnerability_type='SQL Injection',
    severity='critical', details='...')` → `~/.cco/agent_memory.db` SQLite'a
    yazıldı, Knowledge Graph'te node+edge oluştu
  - ✅ `qwen_analyze(target='192.168.1.1', data='Port 22 OpenSSH 7.4, Port 80
    Apache 2.4.49', analysis_type='vulnerability')` → OpenRouter'a
    `qwen/qwen3.6-plus` ile istek gitti, **CVE-2021-41773 doğru tespit edildi**
  - ✅ `ruff check` — All checks passed

### 2026-01-23 — CLAUDE.md v3 (Gerçek Deneyime Göre Revizyon)

Gerçek session'larda yapılan 5 e2e test sonucu **4 kritik davranış bulgusu**
ortaya çıktı ve CLAUDE.md v3'e yansıtıldı:

**Bulgu 1:** `@skills/...` referansları **auto-load ETMEZ** — model sadece
"okumam gerek" diye bahseder, Read tool çağırmaz. → Çözüm: CLAUDE.md'den tüm
`@skills/` referansları kaldırıldı, yerine **3 tetikleme yolu** net yazıldı:
  1. `Skill({"skill": "web-exploit"})` — native Claude Code tool, model'den çağrılır
  2. `/web-exploit` — kullanıcı prompt'unun ilk satırında (model yazınca metin olur)
  3. `Read(file_path="/app/.claude/skills/<name>/SKILL.md")` — fallback

**Bulgu 2:** Skills **yanlış konumdaydı** (`/app/skills/`). Claude Code native
Skills mekanizması `~/.claude/skills/` veya `.claude/skills/` altında arar.
→ Çözüm:
  - `/app/skills/` → `/app/.claude/skills/` taşındı (backward-compat symlink ile)
  - `~/.claude/skills/<name>` → `/app/.claude/skills/<name>` symlink'leri oluşturuldu
  - `install-cco.sh`'a otomatik symlink creation eklendi (PHASE 3)
  - Sonuç: `claude -p "/tools"` sorgusunda 7 skill slash command göründü
    (`/recon-enumeration`, `/web-exploit`, `/web-advanced`, `/binary-pwn`,
    `/crypto-forensics`, `/ctf-solver`, `/report-generator`)

**Bulgu 3:** `skills/web-advanced/SKILL.md` dosyasında **YAML frontmatter eksik**
idi (diğer 6 skill'de vardı). → Çözüm: name/description frontmatter eklendi,
Anthropic Agent Skills format uyumu sağlandı.

**Bulgu 4:** Model tool-use davranışı **orchestrator modele göre değişiyor**:
  - `meta-llama/llama-3.3-70b-instruct` → `Skill` tool'unu düzgün çağırır ✅
  - `qwen/qwen3-next-80b-a3b-instruct` → bazen `Skill({"skill":"..."})` metin
    olarak yazar, tool_use oluşturmaz ⚠️
  → Çözüm: CLAUDE.md'ye "Kullanıcı Workflow Önerisi" bölümü eklendi —
    kullanıcının slash command kullanması, orchestrator modelden bağımsız
    **garantili yol** olarak tanıtıldı. `.env`'de model değiştirme örnekleri
    eklendi.

**Bulgu 5:** Minimum prompt'ta model **memory'e kayıt yapmıyordu**. →
Çözüm: CLAUDE.md başına **"MUTLAK KURALLAR"** bölümü eklendi:
  - Kural 1: İlk aktif tool çağrısından ÖNCE Skill tetikle
  - Kural 2: Her tool sonucundan sonra `store_finding/credential/endpoint`
  - Kural 3: Scope enforcement
  - Kural 4: Model delegation (session model sabit, MCP tool delegation)

**Ek değişiklikler:**
- CLAUDE.md 12.6KB → 16.5KB (kural netliği için kabul edilebilir artış)
- `@rules/` ve `@workflows/` referansları inline hale getirildi
- "Çalışmayan Kalıplar" tablosu genişletildi (9 pattern)
- Gerçek session test sonuçlarına göre "kullanıcı workflow önerileri" eklendi
- `install-cco.sh` PHASE 3'e skills symlink bootstrap eklendi

### E2E Test Matrisi (2026-01-23)

| Test | Model | Durum | Bulgu |
|------|-------|-------|-------|
| `Skill(skill="web-exploit")` tool call | llama-3.3-70b | ✅ doğru tool_use | Llama tool use güvenilir |
| Aynı test | qwen3-next-80b | ⚠️ metin olarak yazıldı | Qwen tool use tutarsız |
| `/web-exploit` slash (user prompt) | her ikisi de | ✅ skill launch | **EN GÜVENİLİR YOL** |
| `Read(/app/.claude/skills/.../SKILL.md)` | her ikisi de | ✅ dosya okundu | Fallback çalışıyor |
| `store_finding` otomatik çağrı | qwen3-next-80b | ✅ memory kaydedildi | MUTLAK KURAL'a uyuldu |
| `mcp__kali-tools__nuclei_scan` | her ikisi de | ✅ tool çağrıldı, nuclei yok (container) | Gerçek Kali'de çalışacak |
| `qwen_analyze` → OpenRouter | tool içi qwen3.6-plus | ✅ CVE-2021-41773 tespit | Model delegation OK |

## Architecture Decisions

### OpenRouter Claude Code compat (Jan 2026)
- `ANTHROPIC_API_KEY` yerine `ANTHROPIC_AUTH_TOKEN` kullan (aksi halde OAuth denenir)
- Base URL `/api` (NOT `/api/v1`) — Claude Code kendisi `/v1/messages` ekler
- `ANTHROPIC_DEFAULT_HAIKU_MODEL/SONNET/OPUS` env ile alias mapping yap,
  çünkü Claude Code varsayılan olarak Anthropic model listesini validate eder
- Thinking-only modeller session modeli değil — `qwen/qwen3.6-plus` sadece
  MCP tool içinden `requests.post` ile çağrılır

### Container compatibility
- Root/sudo container için `IS_SANDBOX=1` env gerekli (Claude Code v2.x)
- `--dangerously-skip-permissions` yerine `--permission-mode bypassPermissions`
  non-interactive modda daha güvenli

## Backlog (P0 / P1 / P2)

### P0 (must-have before real-world use)
- [ ] Her skill dosyasının Claude Code tarafından `@skills/...` ile okunabildiğini
      (lazy-load) gerçek bir bug bounty senaryosunda doğrula
- [ ] `scope-guard.md` ve `safety-rules.md` işletme davranışını (`/scope add`
      REPL komutu yerine doğal dil "scope: 10.10.10.0/24" ile) gerçek test et

### P1 (nice-to-have)
- [ ] `mcp-browser` server'ını install-cco.sh'da default olarak kayıt et
      (playwright yüklüyse)
- [ ] `telemetry` MCP server'ına OpenRouter `usage.cost` alanını otomatik çekme
- [ ] `rag-engine` ilk çalıştırmasında Exploit-DB/CVE feed'ini bootstrap et
- [ ] TryHackMe/HTB session resume (Claude Code'un kendi `--resume` session'ı
      ile entegrasyon test)

### P2 (future)
- [ ] `bug-bounty-workflow.md` için custom slash command `/bugbounty <target>`
- [ ] Web UI (Claude Code for VSCode ile entegrasyon)
- [ ] Docker image (pre-built Kali + CCO)

## Test Credentials
Bu proje kullanıcı authentication içermez — OpenRouter API key'i tek credential.
Key `.env` dosyasında, chmod 600 ile korumalı. Detay: `/app/memory/test_credentials.md`.

## Risks & Mitigations

| Risk | Durum | Önlem |
|------|-------|-------|
| OpenRouter Claude Code tool use compat | ✅ Doğrulandı (qwen3-next-80b-a3b-instruct) | Faz 0'da test edildi |
| MCP server'lar `hackeragent` import alır | ✅ Yok | `grep` ile doğrulandı, 0 import |
| CLAUDE.md büyük (12.6KB) | ✅ Kabul edilebilir | Skills/workflows @reference ile lazy-load |
| Hermes 405B session modeli olarak | ✅ Önlendi | Sadece `generate_exploit_poc` tool içinden |
| Thinking model session'da boş result | ✅ Önlendi | `ANTHROPIC_DEFAULT_SONNET_MODEL=qwen3-next-80b-a3b-instruct` (non-thinking) |
| Root container'da permission reddi | ✅ Önlendi | `.env` içinde `IS_SANDBOX=1` |

## Next Actions
1. Kullanıcı Kali ortamında `./install-cco.sh` çalıştırsın; gerçek tools
   (nmap, sqlmap vs.) container'da eksik olabilir, Kali'de tam çalışır
2. TryHackMe / HackTheBox Easy makine ile Faz 3 real-usage test
3. `telemetry` ile session maliyet dashboard'unu kullan
4. CLAUDE.md'yi ilk deneyime göre güncelle
