---
name: attack-surface-mapping
description: "Pasif OSINT ve client-side keşif ile saldırı yüzeyi haritalama skill'i. Hedefe doğrudan saldırmadan, Certificate Transparency (crt.sh), DNS recon, Wayback Machine arşivi, RDAP/WHOIS, GitHub dork, kullanıcı adı OSINT ve headless tarayıcı (Playwright) analizi ile maksimum bilgi toplar. Bu skill'i şu durumlarda kullan: kullanıcı 'saldırı yüzeyi', 'attack surface', 'pasif keşif', 'passive recon', 'OSINT haritalama', 'subdomain bul (pasif)', 'crt.sh', 'wayback', 'arşiv URL', 'github dork', 'leak ara', 'kullanıcı adı ara', 'sosyal medya OSINT', 'API endpoint keşfi', 'security header', 'cookie audit', 'DOM XSS', 'JS endpoint' dediğinde veya bir domain/kurum hakkında temas kurmadan istihbarat toplaması istendiğinde. mcp-osint-tools ve mcp-browser server'larını birlikte kullanan ilk-temas-öncesi keşif metodolojisi."
---

# 🗺️ Saldırı Yüzeyi Haritalama (Attack Surface Mapping)

Hedefe **tek bir aktif paket göndermeden** maksimum istihbarat toplama skill'i.
Bug bounty ve pentest'lerin EN ÖNEMLİ ilk fazı — yüzey ne kadar genişse,
saldırı vektörü o kadar çoktur. İki MCP server'ı birlikte kullanır:

- **`mcp-osint-tools`** → pasif istihbarat (DNS, CT log, arşiv, WHOIS, leak)
- **`mcp-browser`** → client-side keşif (JS endpoint, header, cookie, DOM)

> ⚖️ **Scope:** Pasif OSINT kaynakları (crt.sh, archive.org, rdap.org, github.com)
> allowlist'tedir; scope dışı hedeflerde bile güvenle çalışır. Browser tool'ları
> hedefle TEMAS kurar — yalnızca scope içi veya public test lab'larda kullan.

---

## Faz 1: Pasif DNS & Domain İstihbaratı (temas yok)

```
# Certificate Transparency loglarından subdomain çıkar (en güçlü pasif kaynak)
mcp__osint-tools__crtsh_subdomains(domain="example.com")

# Kapsamlı DNS kaydı: A/AAAA/MX/NS/TXT/CNAME/SOA + SPF/DMARC tespiti
mcp__osint-tools__dns_recon(domain="example.com")

# Zone transfer (AXFR) zafiyeti dene — açıksa kritik bulgu
mcp__osint-tools__dns_zone_transfer(domain="example.com")

# Domain kayıt bilgisi (registrar, tarihler, NS) — API key gerekmez
mcp__osint-tools__rdap_whois(domain="example.com")
```

**Bulgu olarak kaydet:** Her subdomain bir `store_endpoint`, AXFR açıksa
`store_finding(severity="critical")`.

---

## Faz 2: Tarihsel & Kod Tabanlı İstihbarat (temas yok)

```
# Wayback Machine — eski/unutulmuş endpoint ve parametreli URL'ler
mcp__osint-tools__wayback_urls(domain="example.com", only_params=True)

# GitHub'da sızdırılmış secret / config / endpoint avı
mcp__osint-tools__github_code_search(query="example.com api_key")
mcp__osint-tools__github_code_search(query="org:example filename:.env")
#   → Gerçek KOD araması için GITHUB_TOKEN env ver (yoksa repo araması yapar)

# Kurum/kişi kullanıcı adı parmak izi (14 platform)
mcp__osint-tools__username_osint(username="targetcorp")
```

> `wayback_urls(only_params=True)` çıktısı doğrudan Faz 4 (DOM XSS / IDOR)
> için test edilecek parametre listesi sağlar.

---

## Faz 3: Client-Side Keşif (headless browser — temas var)

```
# JS-render sonrası tüm link/script/form + parametreli URL'ler
mcp__browser__browser_extract_links(url="https://example.com")

# SPA'nın arka planda konuştuğu gizli API endpoint'leri
mcp__browser__browser_capture_requests(url="https://example.com")

# JS console hataları → stack trace / debug / leak ipuçları
mcp__browser__browser_console_logs(url="https://example.com")
```

**Çıktı zinciri:**
- `browser_extract_links.js_files` → `mcp__kali-tools` linkfinder/secretfinder ile tara
- `browser_capture_requests.api_requests` → `web-advanced` ile API fuzzing
- `browser_extract_links.urls_with_params` → Faz 4 girdisi

---

## Faz 4: Pasif Güvenlik Konfigürasyon Denetimi

```
# Eksik güvenlik başlıkları (CSP/HSTS/X-Frame-Options...) + info disclosure
mcp__browser__browser_security_headers(url="https://example.com")

# Cookie güvenlik flag'leri (HttpOnly/Secure/SameSite) → session/CSRF riski
mcp__browser__browser_cookie_audit(url="https://example.com")

# DOM-based XSS reflection probe (non-destructive canary)
mcp__browser__browser_dom_xss_probe(url="https://example.com/search", param="q")
```

---

## Çıktı → Sonraki Skill Akışı

| Bu skill'in bulgusu | Devam edilecek skill / tool |
|---------------------|------------------------------|
| Yeni subdomain'ler | `recon-enumeration` (aktif port/dizin tarama) |
| Parametreli URL'ler | `web-exploit` (SQLi/XSS/LFI test) |
| Gizli API endpoint'leri | `web-advanced` (GraphQL/JWT/IDOR matrix) |
| AXFR açık / eksik header | `report-generator` (CVSS + rapor) |
| GitHub leak / secret | `source-code-review` (SAST) |
| Kullanıcı adları / e-postalar | `osint-password-spraying` |

---

## Metodoloji İlkeleri

1. **Önce pasif, sonra aktif** — Faz 1-2 hedefe iz bırakmaz; mümkün olan her
   şeyi temas öncesi topla.
2. **Her bulguyu memory'e kaydet** — `store_endpoint`, `store_finding`,
   `store_credential`. Knowledge Graph attack path'i besler.
3. **Yüzeyi katmanla** — crt.sh + Wayback + browser link'leri birleşince
   tek kaynağın kaçırdığını yakalarsın.
4. **Çıktıyı zincirle** — bu skill keşif yapar; exploit'i ilgili skill devralır.
5. **Scope disiplini** — pasif OSINT serbest; browser/aktif tool sadece scope içi.
