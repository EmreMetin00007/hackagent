---
description: "Tek komutla otonom recon→exploit zinciri: pasif OSINT, aktif keşif, zafiyet exploit ve rapor. Knowledge Graph ile fazları zincirler."
argument-hint: "<hedef-domain-veya-IP> [scope: ek-hedefler]"
---

# /pwn — Otonom Recon → Exploit Zinciri

Hedef: **$ARGUMENTS**

`workflows/recon-to-exploit-workflow.md` iş akışını **baştan sona otonom** yürüt.
Kullanıcı yalnızca scope tanımlar ve kritik adımlarda onay verir; geri kalan her
şeyi sen koordine et.

## Yürütme Protokolü

1. **Scope doğrula** — `rules/scope-guard.md`. $ARGUMENTS içinde `scope:` yoksa
   yalnızca pasif OSINT (Faz 1) yap; aktif tool için kullanıcıdan scope iste.
2. **Workflow'u yükle** — `Read('/app/workflows/recon-to-exploit-workflow.md')`.
3. **Faz 0 — Memory:** `mcp__memory-server__get_target_memory` +
   `query_attack_paths` (geçmiş bulgu varsa Faz 4'e atla).
4. **Faz 1 — Pasif OSINT:** `Skill({"skill": "attack-surface-mapping"})` →
   crt.sh, dns_recon, wayback, rdap, github dork. Her bulgu → `store_endpoint`/`store_finding`.
5. **Faz 2 — Aktif keşif** (scope içi): `Skill({"skill": "recon-enumeration"})` →
   parallel_recon, nmap, ffuf, nuclei + browser client-side keşif.
6. **Faz 3 — Karar:** `suggest_next_action` + `query_attack_paths` → en yüksek
   impact'li vektörü seç.
7. **Faz 4 — Exploit:** uygun skill (`web-exploit` / `web-advanced` / `llm-security`).
   Exploit/lateral öncesi **`request_approval` ZORUNLU** — onaysız ACT yok.
8. **Faz 5 — Rapor:** `Skill({"skill": "report-generator"})` + `get_cost_summary`.

## Kurallar
- Her fazdan sonra memory'e yaz (MUTLAK KURAL 2).
- Yeni subdomain/endpoint bulunursa Faz 2'ye dön (sürekli döngü).
- OPSEC: bug bounty'de yavaş + düşük paralellik (`generate_stealth_curl`).
- Tehlikeli aksiyonlarda dur ve kullanıcı onayı iste.

Şimdi **$ARGUMENTS** hedefi için zinciri başlat.
