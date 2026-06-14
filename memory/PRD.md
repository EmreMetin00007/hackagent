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
### 2026-06-14 — `mcp-hunter` P1: Auto-Fanout (kali-tools) + RAG Enrichment (rag-engine)

Kullanıcı isteği: "`hunt_variants`'ı kali-tools'a auto-fanout olarak bağla (doğrulanan bug →
varyantları otomatik çalıştır+doğrula); `predict_vulnerabilities` çıktısını rag-engine'e
otomatik besleyip CVE PoC'larını çekme." → `mcp-hunter` 6→8 tool.

- **H6 `auto_fanout_variants`** (kali-tools köprüsü): doğrulanan bir bug'ı alır, çalıştırılabilir
  varyantları üretir. **PLAN modu (offline, varsayılan):** her varyant için `mcp__kali-tools__
  curl_request(...)` + `mcp__validator__validate_*(...)` çağrılarından FANOUT PLANI döndürür.
  **LIVE modu:** GET-tabanlı güvenli varyantları (kardeş param + header konumu) gerçekten gönderir
  (validator tarzı `requests`), sınıfa-özel hızlı triage oracle uygular (XSS yansıma / SQL-hata
  imzası / LFI passwd / open-redirect Location / cmdi uid / differential) → LIKELY varyantları
  kesin doğrulama için validator'a devreder. Yıkıcı sınıflar (rce/upload/cmdi/deserialization)
  canlıda atlanır (`allow_mutations` gerekir); `max_requests` rate-limit/OPSEC guard.
- **H7 `enrich_with_rag`** (rag-engine köprüsü): `predict_vulnerabilities` çıktısını otomatik
  RAG'a bağlar. Tahminlerin `cve_families`'inden CVE ID'leri regex ile çıkarır; rag-engine'in
  kullandığı **aynı ChromaDB**'yi (`CCO_HOME/rag_db`) read-only inline sorgular → eşleşen
  PoC/exploit/CVE hit'leri (relevance-scored). DB boşsa graceful: `rag_ingest_cve` +
  `rag_ingest_exploitdb` + `rag_search` INGEST PLANI döndürür. "Stack tahmini → somut PoC".
  Tek çağrıyla predict→rag (predictions_json verilmezse içeride predict çalıştırır).

**Entegrasyon:** CLAUDE.md Kural 7 akışına 1b (RAG PoC) + 5 (auto-fanout LIVE) eklendi; skill
flow + README server tablosu/bug-hunting bölümü/profil tablosu güncellendi. Tool guard 6→8,
toplam 225→227. cco-profile/token-estimate otomatik (list_tools).

**Doğrulama:** ✅ `pytest -q` → **137 passed, 1 skipped** (5 yeni test: fanout PLAN offline,
yıkıcı-sınıf canlı atlama, **canlı XSS yansıma triage** loopback reflektör sunucuya karşı →
LIKELY, RAG CVE çıkarımı + ingest/search planı, predictions_json kabulü). Canlı demo: Laravel/
Apache/Struts → CVE-2021-3129/41773/2017-5638 çıkarıldı + ingest_plan üretildi; SQLi fanout →
11 varyant + curl + validate_sqli followup. ruff temiz. Hiçbir flow mock değil; inline RAG
chromadb yoksa graceful plan'a düşer.


### 2026-06-14 — Bug-Hunting Intelligence: `mcp-hunter` (scanner → hunter)

**Kullanıcı isteği:** "Mimari olarak güçlendirme — daha çok ZEKA ve BUG BULMA etkileyecek
yollar." (SaaS/dashboard değil; çekirdek zeka + gerçek zafiyet keşfi.)

**Tespit:** Mevcut set enjeksiyon sınıfında güçlü (validator: SQLi/XSS/SSTI/cmdi/LFI/SSRF/
XXE) ama bug bounty'de **en çok ödeyen** sınıflarda zayıftı: Broken Access Control (OWASP
Web #1, API #1/#5 — BOLA/BFLA/IDOR), iş mantığı (fiyat/kupon/race), variant analizi
(çoğaltma), kapsama (kaçırılan bug). Bunlar imza ile değil akıl yürütme ile bulunur.

**Yapılanlar — yeni 14. server `mcp-hunter` (6 tool, tamamen deterministik çekirdek; LLM
varsa H1/H3 zenginleşir, yoksa graceful):**
- **H1 `predict_vulnerabilities`** — teknoloji parmak izinden (fingerprint + memory endpoint
  tech) muhtemel zafiyet sınıflarını + CVE ailelerini DETERMİNİSTİK tahmin eder; 30+ tech
  imza DB'si (wordpress/apache/struts/spring/laravel/graphql/jwt/s3/jenkins...), her tahmin
  için hedefli hipotez + RAG sorgusu + validator hook + tetikleyici skill. "Körlemesine
  tarama → stack'e özel hipotez".
- **H2 `build_authz_matrix` + `analyze_authz_result`** — çok-kimlikli (anon/userA/userB/admin)
  × kaynaklar **BOLA/BFLA/IDOR farksal test matrisi** (object-level vs function-level
  sınıflama + obje id substitution + method tampering) ve **farksal ORACLE**: owner (kontrol)
  vs attacker (test) yanıtı — aynı 2xx içerik (byte-hash eşleşmesi / paylaşılan owner
  işaretçileri) = yetki ihlali KANITI (LLM görüşü değil, ölçülebilir; false-positive guard).
- **H3 `generate_abuse_cases`** — parametre semantiğine göre **business-logic abuse** (fiyat/
  miktar/rol/kupon/OTP/iş-akışı/tarih) + jenerik endpoint saldırıları (race condition, mass
  assignment, replay, adım atlama). AI'nın tarayıcıyı ezdiği sınıf.
- **H4 `hunt_variants`** — DOĞRULANMIŞ bir bulgudan kardeş param/endpoint (memory'den)/method/
  content-type/injection-konumu/subdomain'de aynı sınıfı **sistematik çoğaltır** → tek bug'dan
  sürü (bug bounty avcısının elle yaptığı çoğaltmanın otomasyonu).
- **H5 `coverage_report`** — (endpoint × vuln-class) test edildi/edilmedi matrisi (findings +
  lessons'tan), tamamlanma %, en değerli TEST EDİLMEMİŞ boşluklar + çekirdek grup (access_
  control/business_logic/...) **kör nokta** uyarısı → kaçırılan bug (false-negative) guard'ı.

**Entegrasyon:** CLAUDE.md **Kural 7 (bug-hunting akışı)** + protokol skill satırı + ekosistem
tablosu (14 server/225 tool). Yeni skill `access-control-hunting` (23. skill) + reasoning
`recommend_skills` SKILL_SIGNALS'a eklendi (additive). install-cco.sh (hunter kaydı + import
loop), cco-profile.sh (web/recon/full'a hunter), token-estimate.py, README güncellendi.
**13→14 server, 219→225 tool (reasoning gerçekte 19; eski doküman 218'i 1 hatalıydı, düzeltildi),
22→23 skill.**

**Doğrulama:** ✅ `pytest -q` → **132 passed, 1 skipped** (yeni `test_hunter.py`: 14 test —
predict tech→vuln + memory okuma + bilinmeyen-stack advice, authz matrisi BOLA/BFLA/unauth
sınıflama + id substitution, oracle hash-match CONFIRMED / 403 UNCONFIRMED / BFLA / unauth,
abuse case price/role/race + impact sıralama, variant sibling stratejileri + EV sıralama,
coverage gaps + kör nokta). ✅ Offline demo (Laravel/JWT/Apache hedefi): predict CVE-2021-3129
+ JWT BFLA tahmin etti; authz matrisi /admin/export→BFLA, /api/orders/{id}→BOLA üretti; oracle
owner==attacker hash → CONFIRMED (0.92); coverage access_control/business_logic kör noktası
işaretledi. Tüm akış network/LLM olmadan çalışıyor.


### 2026-06-14 — Reverse-Proxy + WAF Intelligence (a+b+c)

**Kullanıcı problemi:** CCO özellikle reverse-proxy/CDN + WAF'lı hedeflerde zorlanıyordu
(kör payload, origin keşfi yok, blok sınıflandırma yok). Seçim: a+b+c birlikte.

**Yapılanlar (`mcp-reasoning` 14 → 18 tool; deterministik, canlı işlemler kali-tools'a delege):**
- **(a) `fingerprint_waf`** — 12 vendor imzası (Cloudflare/Akamai/Imperva/AWS/F5/ModSecurity/
  Sucuri/Fortiweb/Azure/Fastly...) header/cookie/blok-sayfasından tespit; vendor'a etkili
  evasion operatörleri + CDN ise origin-keşfi önerisi.
- **(b) `discover_origin`** — CDN/WAF arkasındaki gerçek backend IP'sini bulur: leaked-header/
  tarihsel-DNS/CT/favicon sinyallerini sıralar, **CDN IP öneklerini eler** (Cloudflare/Fastly),
  Host-override doğrudan-origin testleri + crt.sh/Shodan/Censys/dig canlı recon komutları üretir.
  Origin'e doğrudan gitmek **WAF'ı tümden atlar** (bu hedeflerdeki en büyük kazanç).
- **(c) `classify_response`** (waf_block/rate_limit/app_error/origin_reached) + **`adaptive_evasion_step`**
  (kapalı-döngü: sınıflandır→fingerprint→`evolve_payload(waf=...)`→öğren; rate-limit'te throttle,
  CDN'de origin baypası önerir) + **`evolve_payload` artık WAF-aware** (`waf` param → vendor'a
  tercihli operatörleri öne alır).

**Doğrulama:** ✅ `pytest -q` → **111 passed, 1 skipped** (yeni `test_reasoning_waf.py`: 13 test —
vendor fingerprint, blok sınıflandırma, origin sıralama+CDN eleme, WAF-aware operatör
önceliklendirme, kapalı-döngü). Demo: cloudflare tespit→origin adayı sıralandı→case_swap
öncelikli varyantlar→adaptif döngü origin baypası önerdi. Sayaçlar: **14→18 tool, 214→218 toplam**.


### 2026-06-14 — CLAUDE.md Orkestratör Kuralı + TryHackMe Deneme Rehberi

**Kullanıcı isteği:** Orkestratör akışının gerçek session'da garanti tetiklenmesi için
kural netleştir; ayrıca TryHackMe/Kali'de deneme rehberi.

**Yapılanlar (doküman — kod değişmedi):**
- **CLAUDE.md Kural 6 yeniden yazıldı:** `deep_think` artık "ZORUNLU İLK tool çağrısı"
  olarak konumlandı; çıktının `step_0_recommended_skills.kickoff` slash-command'ı
  "prompt'un İLK SATIRI olarak AYNEN çalıştırılmalı" (model-bağımsız garanti tetikleme).
  step_0→step_5 orkestratör çıktısı + 6 yeni beyin tool'u listelendi.
- **Öncelik Sırası** güncellendi: 1) scope → 2) deep_think (ilk çağrı) → 3) kickoff skill.
- **Önerilen ilk komutlar**'a "⭐ ORKESTRATÖR-FIRST" örneği eklendi (`/deep-reasoning <IP>`).
- **Yeni rehber:** `workflows/tryhackme-orchestrator-test.md` — iki-paslı gerçekçi akış
  (taze hedef→recon→memory→deep_think tekrar→kill-chain→validate→score→learn), önerilen
  THM odaları (Vulnversity/RootMe/Pickle Rick/OWASP Top 10), başarı kriteri checklist'i,
  sorun giderme tablosu, maliyet tahmini.

**Not:** Bu akış README için ilk **validator-onaylı kill-chain kanıtını** üreten akıştır.
`pytest` etkilenmedi (98 passed, 1 skipped — yalnızca markdown değişti).


### 2026-06-14 — Auto-Skill Router (c) + deep_think Orkestratör Köprüsü

**Kullanıcı seçimi:** (c) Auto-Skill Router + "pazarlama köprüsü": deep_think otomatik
compose_attack_chains çağırsın → tek komutta recon→zincir→doğrula→skorla.

**Yapılanlar (`mcp-reasoning` 13 → 14 tool):**
- **(c) `recommend_skills`** — hedef parmak izine (memory teknolojileri/bulguları + serbest
  metin) göre HANGİ skill'in çalışacağını DETERMİNİSTİK seçer ve tam tetikleme komutunu
  (`/web-exploit <hedef>` vb.) + kickoff verir. 22 skill için sinyal kataloğu + bulgu→skill
  haritası + faz ayarı (memory boşsa keşif önce). Dokümante "model skill'i tetiklemiyor"
  tutarsızlığını çözer.
- **deep_think orkestratör köprüsü** — artık tek çağrıda: step_0 `recommend_skills` →
  step_1 dersler → step_2 plan → **step_2b `compose_attack_chains` (kill-chain + report)** →
  step_3 seçilen vektör → step_4 reflexion → **step_5 `exploitability_score` ön-skoru** +
  `pipeline` ("recon→zincir→doğrula→skorla→exploit→öğren") + 5 adımlı next_steps.

**Doğrulama:** ✅ `pytest -q` → **98 passed, 1 skipped** (yeni `test_reasoning_router.py`:
7 test — fresh-recon fazı, web-advanced/cloud/AD sinyal yönlendirme, exploitation fazı
bulgu→skill, slash-command tetikleyiciler, deep_think'in zincir+skor+skill köprüsü).
Sayaçlar: **13→14 reasoning tool, 213→214 toplam** (README/CLAUDE/test guard güncellendi).


### 2026-06-14 — Zeka Katmanı v2: Kill-Chain Intelligence + Payload Evolution + Exploitability Score

**Kullanıcı seçimi:** "skill/zeka tarafını piyasayı kasıp kavuracak" 3 farklılaştırıcı,
birlikte: (a) Attack Chain Composer, (d) WAF-aware Payload Evolution, (e) Exploitability
Score. Hepsi mevcut reasoning/validator/memory altyapısına eklendi, tamamen deterministik
(LLM/network gerekmez) → bu ortamda offline test edildi.

**`mcp-reasoning`'e 5 yeni tool (8 → 13):**
- **(a) `compose_attack_chains`** — memory'deki bulguları deterministik ÇOK-ADIMLI
  kill-chain'lere bağlar (yetenek grafiği + Bayesçi EV). Örn. SSRF→IMDS→IAM→bulut
  ele geçirme, LFI→log poisoning→RCE, IDOR→ATO, open-redirect→OAuth token→ATO.
  Bileşik olasılık (entry blended_prob × Π edge feasibility) × yükseltilmiş impact ×
  effort → EV ile sıralar. Tek orta-seviye bulguları KRİTİK etkiye dönüştürür
  (büyük ödülleri kazandıran şey; HexStrike/CAI'de yok). Her adım validator hook'lu.
- **(a) `kill_chain_report`** — bir zinciri reprodüklenebilir Markdown saldırı
  anlatısına (adım/pivot/fizibilite/validator komutu) çevirir (XBOW-tarzı validated trace).
- **(d) `evolve_payload`** — WAF blok sinyaline göre payload'ı guided/genetik mutasyonla
  evrimleştirir (17 operatör: inline_comment, keyword_split, ${IFS}, tag-breakup,
  unicode_slash...). Tekniğe göre operatör ailesi; lessons-ağırlıklı fitness.
- **(d) `record_payload_result`** — operatör başarı oranını öğrenir (`payload_ops`
  tablosu) → evolve_payload fitness'ına karışır (WAF'a karşı zamanla akıllanır).
- **(e) `exploitability_score`** — validator confidence + reflexion verdict + öğrenilmiş
  win-rate + kanıt bütünlüğü → tek kalibre skor + band (CONFIRMED/LIKELY/POSSIBLE/
  UNLIKELY) + false-positive riski + kanıt anlatısı. Validator yoksa üst sınır 0.65
  (deterministik doğrulama olmadan CONFIRMED iddia edilemez) → "güven" ticari moat.

**Doğrulama:** ✅ `pytest -q` → **91 passed, 1 skipped** (yeni `test_reasoning_intel.py`:
13 test — çok-adımlı zincir kompozisyonu, SSRF→cloud & LFI→RCE zincirleri, EV sıralama,
kill-chain report, payload signal-break, öğrenmenin fitness'ı yükseltmesi, exploitability
validator-var/yok ayrımı). ✅ Offline demo: 5 kill-chain EV ile sıralandı, payload
'UNION' bloğunu kırdı, exploitability validator'sız 0.618'de tavanlandı + doğrulama önerdi.
Sayaçlar: **8→13 reasoning tool, 208→213 toplam** (README/CLAUDE/test guard güncellendi).


### 2026-06-14 — Benchmark Harness v1.1: Kanıt Bütünlüğü (anti-cheat + reprodüksiyon)

**Tetik:** Kullanıcı "benchmark bu haliyle ticari kanıt için yeterli mi?" diye sordu.
Tespit: mevcut `--mock` koşusu yalnızca harness mantığını test ediyor (skor
`solution.json`'dan okunuyor) ve scorecard mock %75'i XBOW %76.9 ile kıyaslayıp
**gerçek capability sanılabilecek yanıltıcı bir çerçeve** üretiyordu → ticari
kanıt için YETERSİZ.

**Yapılanlar (`scripts/xbow_benchmark.py` → v1.1, tamamen offline doğrulandı):**
- **Anti-cheat / echo guard:** Yakalanan flag solver prompt'unda zaten varsa
  `flag_in_input=True` → SOLVED sayılmaz (hallüsinasyon/kopya koruması).
- **Validator-onaylı çözüm metriği:** Çıktıda `CONFIRMED`/`confidence≥0.5` izi →
  `validator_confirmed`; scorecard "X/Y validator-onaylı" satırıyla LLM iddiasını
  oracle kanıtından ayırır.
- **Reprodüksiyon metadata** (`run_metadata`): mode, is_capability_evidence,
  model, git_commit, python, host, generated → her `results.json`'a gömülür.
  Per-challenge **transcript** (`~/.cco/benchmark/transcripts/<id>.log`).
- **MOCK watermark:** Mock scorecard başına "SELF-TEST — YETENEK KANITI DEĞİLDİR"
  uyarısı; XBOW delta kıyası mock modda **bastırıldı** (yalnızca docker modda gösterilir).
- **Operasyonel (gerçek 104-run için):** `--resume` (çözülmüşleri atla),
  `--max-cost` (toplam USD tavanı / runaway koruması), `--junit` (CI/yayın export).
- Doküman: README benchmark bölümü + `workflows/benchmark-workflow.md` v1.1 notları.

**Doğrulama:** ✅ `pytest -q` → **78 passed, 1 skipped** (yeni
`tests/test_xbow_benchmark_integrity.py`: 10 test — echo guard, validator sayımı,
mock watermark vs docker delta ayrımı, metadata, resume, max-cost, junit).
✅ `run --all --mock --junit` → MOCK watermark'lı scorecard + JUnit XML + metadata üretildi.

**Önemli sınır:** Gerçek capability skoru bu preview ortamında ÜRETİLEMEZ — Docker +
`claude` CLI + OpenRouter key + `validation-benchmarks` repo gerekir (Kali host'ta).
Harness "yayınlanabilir kanıt" seviyesine hazır; #1 ticari açık (gerçek skor kanıtı)
için kullanıcının kendi ortamında `--repo` (docker) koşusu şart.


### 2026-06-14 — DeepSeek entegrasyonu (reasoning beyni için güçlü provider)

**Tetik:** Kullanıcı kendi DeepSeek API anahtarını verdi; reasoning beynini güçlü bir
reasoning modeliyle çalıştırmak istedi. (Güvenlik: anahtar açık paylaşıldı → kullanıcıya
rotate etmesi söylendi; anahtar hiçbir dosyaya/commit'e yazılmadı.)

**Yapılanlar (integration_expert playbook'una göre, OpenAI-uyumlu):**
- `mcp-reasoning` server'ı **provider-aware** yapıldı. `_provider_for(model)` model adına
  göre yönlendirir: `deepseek*` → `https://api.deepseek.com/chat/completions` (Bearer
  DEEPSEEK_API_KEY), aksi → OpenRouter. `_chat()` her iki sağlayıcıyı destekler;
  DeepSeek reasoning yanıtındaki `reasoning_content` yok sayılır (yalnızca final content).
- **Otomatik geçiş:** `DEEPSEEK_API_KEY` varsa beyin otomatik DeepSeek'e geçer →
  actor/planner=`deepseek-reasoner`, critic=`deepseek-chat`. Yoksa OpenRouter Qwen/Hermes.
  `CCO_REASON_MODEL`/`CCO_CRITIC_MODEL` açık override kazanır. Anahtar env > keyring >
  `~/.cco/config.yaml`'dan okunur — koda gömülmez. install-cco.sh reasoning env block'undan
  hardcode model'ler kaldırıldı (auto-detect için).
- README/CLAUDE.md/skill güncellendi (DeepSeek varsayılan provider notu + anahtar saklama uyarısı).

**Doğrulama:** ✅ Offline: 3 yeni provider testi (routing, model auto-switch, no-key fallback).
✅ CANLI smoke (kullanıcı anahtarı, inline): `deepseek-chat` → "CCO_DEEPSEEK_OK"; tam Reflexion
döngüsü `deepseek-reasoner`(actor)+`deepseek-chat`(critic) → XSS PoC üretip critic REVISE verdi,
`validate_xss_reflection` önerdi. `pytest -q` → **68 passed, 1 skipped.**


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
