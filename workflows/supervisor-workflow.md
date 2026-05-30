# Supervisor Workflow v2.0
**Ajan Koordinasyonu & Knowledge Graph & Swarm Yönetimi**

Bu iş akışı, hedefin sınırlarının geniş olduğu (Bug Bounty, Internal Pentest vb.) ve tek bir orkestratör oturumunun tüm bilgileri tutmakta zorlanacağı durumlarda **Takım Lideri (Supervisor)** rolü üstlendiğinde uygulanmalıdır.

## Temel Kurallar
1. Tüm keşif çıktılarını `memory-server`'a yaz → Knowledge Graph otomatik güncellenir
2. `parallel_recon` ile keşfi 4x hızlandır
3. `suggest_next_action` ile sonraki adımı graph'a sor
4. Kritik operasyonlarda `request_approval` kullan
5. Her engagement sonunda `self_improve` ile öğren

## Faz 1: Hafıza Taraması → Knowledge Graph Kontrolü
Göreve başlarken hedefe daha önce saldırılıp saldırılmadığını kontrol et.
- [ ] `get_target_memory("hedef.com")` çalıştır → Graph özeti dahil gelir
- [ ] `get_knowledge_graph_summary("hedef")` ile detaylı graph durumu
- [ ] Daha önceden bulunmuş açık portlar, credential'lar var mı?
- [ ] Attack path mevcut mu? → `query_attack_paths("target:hedef", "root")`
- [ ] Varsa doğrudan **Faz 3**'e geç. Yoksa keşfi başlat.

## Faz 2: Paralel Keşif → Graph Zenginleştirme
- [ ] `parallel_recon("hedef", "nmap,ffuf,whatweb,nuclei")` — 4 araç aynı anda!
- [ ] `osint_harvest("hedef.com")` — Pasif keşif (email, subdomain)
- [ ] `cloud_enum("hedef")` — S3/Azure/GCP bucket keşfi
- [ ] Her yeni endpoint → `store_endpoint()` (Graph otomatik güncellenir)
- [ ] Her credential → `store_credential()` (Credential chain otomatik)
- [ ] Manuel ilişki ekleme → `add_relationship("service:ssh:22", "software:OpenSSH_8.9", "RUNS")`
- [ ] RAG'dan benzer exploit ara → `rag_search("Apache 2.4 RCE")`

## Faz 3: Akıllı Saldırı → Graph-Driven Decision
Bu fazda Knowledge Graph sonraki adımı belirler:
- [ ] `suggest_next_action("hedef")` → AI-powered saldırı önerisi al
- [ ] `query_attack_paths("target:hedef", "root")` → En yüksek skorlu path'i seç
- [ ] `find_exploitable_chains("hedef")` → Credential chain + exploit chain fırsatları

### Yüksek Kompleksite Hedeflerde: Swarm Kullan
- [ ] `swarm_dispatch("hedef üzerinde SQL injection testi yap", "recon,exploit", "hedef.com")`
- [ ] VEYA tam pipeline: `swarm_chain("hedef pentest", "recon,exploit,validate,report", "hedef.com")`
- [ ] Hermes 405B PoC: `generate_exploit_poc("sqli", "hedef.com", context)`

### Spesifik Saldırı Vektörleri
- Web form/parametre → `sqlmap_test`, `nuclei_scan`
- Binary servis → `angr_analyze`, `ghidra_headless`
- AD/SMB → `impacket_tool("secretsdump", ...)`, `bloodhound_collect()`
- Git repo → `trufflehog_scan`, `gitleaks_scan`
- API endpoint → `kiterunner_scan`, `gau_urls`
- Sonuç başarılı → `store_finding()` ile zafiyeti graph'a ekle

## Faz 4: Doğrulama → Approval Flow
- [ ] Exploit çalıştırmadan: `request_approval("exploit", "SQL injection", "hedef")`
- [ ] Onay gelince exploit'i uygula
- [ ] Lateral movement: `request_approval("lateral_movement", "pivot to 10.10.10.6", "hedef")`
- [ ] Flag submit (CTF): `request_approval("flag_submit", "FLAG{...}", "challenge")`

## Faz 5: Raporlama & Öğrenme
- [ ] `generate_pentest_report("hedef", "full")` — Otomatik pentest raporu
- [ ] `cvss_calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N")` — CVSS skoru
- [ ] Bug bounty ise: `bb_estimate_bounty("critical", "rce")` — Ödeme tahmini
- [ ] CTF ise: `ctf_auto_writeup("challenge_name", "Web", "FLAG{...}", "adımlar")`
- [ ] Telemetry: `get_metrics_dashboard()` — Maliyet ve performans özeti

## Faz 6: Self-Improvement
- [ ] `self_improve("hedef pentest özeti", findings_count=5, success_rate=0.8, lessons_learned="...")`
- [ ] `end_session()` — Telemetry session sonlandır
- [ ] (Opsiyonel) `drop_target_memory("hedef")` — Engagement verisi temizleme
