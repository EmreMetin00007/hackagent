---
description: "Bug bounty kampanyası başlat: scope-aware pasif/aktif keşif, OWASP zafiyet avı, OPSEC/rate-limit disiplini ve HackerOne/Bugcrowd formatında raporlama."
argument-hint: "<program-domain> [scope: in-scope varlıklar]"
---

# /bugbounty — Bug Bounty Kampanyası

Hedef program: **$ARGUMENTS**

`workflows/bug-bounty-workflow.md` iş akışını yürüt. Ödül optimizasyonu ve
program kurallarına uyum önceliklidir.

## Yürütme Protokolü

1. **Scope & kurallar** — `Read('/app/rules/scope-guard.md')`. In-scope varlıkları
   listele, out-of-scope'u not et. Scope dışı hedefte aktif tool ÇALIŞTIRMA.
2. **OPSEC önce** — bug bounty'de ban koruması: yavaş + düşük paralellik,
   `mcp__web-advanced__generate_stealth_curl` ile stealth istek; agresif paralelden kaçın.
3. **Workflow'u yükle** — `Read('/app/workflows/bug-bounty-workflow.md')`.
4. **Pasif keşif** — `Skill({"skill": "attack-surface-mapping"})`
   (crt.sh subdomain, wayback, github dork, dns_recon).
5. **Aktif keşif** — `Skill({"skill": "recon-enumeration"})` (yalnızca in-scope).
6. **Zafiyet avı** — saldırı yüzeyine göre skill seç:
   `web-exploit` (SQLi/XSS/SSRF/IDOR), `web-advanced` (GraphQL/JWT/smuggling),
   `llm-security` (LLM endpoint varsa), `advanced-api-sec` (API).
7. **PoC + doğrulama** — blind için `interactsh_*`; custom için `generate_exploit_poc`.
   Her bulgu → `store_finding(severity, evidence)`.
8. **Önceliklendir** (ödül): Critical (RCE/Auth bypass/SQLi/SSRF→cloud) > High >
   Medium > Low.
9. **Rapor** — `Skill({"skill": "report-generator"})` → HackerOne/Bugcrowd formatı,
   CVSS, PoC, impact, remediation. `get_cost_summary` ile maliyet özeti.

## Kurallar
- Program scope'una MUTLAK uy; şüphede yazılı onay iste.
- Rate limit/lockout disiplini (özellikle login/spray'de).
- Bulguları sorumlu şekilde raporla; veriyi kötüye kullanma.

Şimdi **$ARGUMENTS** programı için kampanyayı başlat.
