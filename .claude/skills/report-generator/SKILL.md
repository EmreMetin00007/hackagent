---
name: report-generator
description: "Bug bounty ve penetrasyon testi rapor üretici skill'i. HackerOne/Bugcrowd formatında profesyonel zafiyet raporları, CVSS hesaplama, PoC hazırlama, remediation önerileri ve CTF writeup oluşturma. Bu skill'i şu durumlarda kullan: kullanıcı 'rapor yaz', 'report', 'writeup', 'bug bounty rapor', 'zafiyet raporu', 'CVSS hesapla', 'finding raporu', 'PoC hazırla', 'remediation', 'düzeltme önerisi', 'HackerOne', 'Bugcrowd', 'pentest raporu' dediğinde veya bulunan zafiyetlerin raporlanması istendiğinde. Herhangi bir güvenlik bulgusu raporlama, writeup oluşturma veya zafiyet belgeleme görevi olduğunda mutlaka bu skill'i kullan."
---

# 📋 Bug Bounty & Pentest Rapor Üretici

Profesyonel zafiyet raporları, CTF writeup'ları ve penetrasyon testi bulguları oluşturmak için skill.

## Temel İlke

**"İyi bir rapor, bulunan zafiyetin değerini belirler."** Bug bounty'de rapor kalitesi = ödül miktarı.

## Bug Bounty Rapor Şablonu — HackerOne Formatı

```markdown
## Başlık
[Zafiyet Tipi] — [Etkilenen Component] — [Kısa Açıklama]
Örnek: "Stored XSS via Profile Bio Field Leading to Account Takeover"

## Severity
[Critical / High / Medium / Low / Informational]
CVSS v3.1 Vektörü: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
CVSS Skoru: X.X

## Açıklama
[Zafiyetin ne olduğunu açıkla]
[Neden tehlikeli olduğunu belirt]
[Teknik detayları ver]

## Yeniden Üretme Adımları (Steps to Reproduce)
1. [Adım 1 — kesin URL/endpoint]
2. [Adım 2 — göndermek gereken veri/payload]
3. [Adım 3 — gözlemlenen sonuç]
4. ...

## Proof of Concept (PoC)
[Curl komutu, HTTP request, exploit kodu]
```bash
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"param": "MALICIOUS_PAYLOAD"}'
```

### HTTP Request
```http
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=ABC123

{"param": "payload"}
```

### HTTP Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"result": "zafiyet kanıtı"}
```

## Etki (Impact)
[Bu zafiyet exploit edilirse ne olur?]
- Kullanıcı verileri sızabilir
- Hesap ele geçirilebilir
- Sunucuda komut çalıştırılabilir
- Dahili ağa erişilebilir
- vs.

## Etkilenen Varlıklar
- URL: https://target.com/vulnerable/endpoint
- Parameter: `id`
- Endpoint: POST /api/v1/users

## Düzeltme Önerisi (Remediation)
[Zafiyetin nasıl düzeltileceğini açıkla]
1. [Birincil düzeltme]
2. [Alternatif düzeltme]
3. [Ek güvenlik katmanları]

## Referanslar
- [Ilgili CVE veya CWE]
- [OWASP sayfası]
- [Benzer zafiyet raporları]
```

## CVSS v3.1 Hesaplama Kılavuzu

### Attack Vector (AV)
```
Network (N)  — Uzaktan, ağ üzerinden sömürülebilir
Adjacent (A) — Yerel ağda olması gerekir
Local (L)    — Fiziksel/local erişim gerekir
Physical (P) — Fiziksel erişim gerekir
```

### Attack Complexity (AC)
```
Low (L)  — Özel koşul yok, direkt exploit edilebilir
High (H) — Başarı için ek koşullar gerekli
```

### Privileges Required (PR)
```
None (N) — Yetki gerektirmez
Low (L)  — Normal kullanıcı yetkisi yeterli
High (H) — Admin/yüksek yetki gerekir
```

### User Interaction (UI)
```
None (N)     — Kullanıcı etkileşimi gerektirmez
Required (R) — Kurbanın bir şey yapması lazım (link tıklama vs.)
```

### Scope (S)
```
Unchanged (U) — Sadece zafiyetli bileşen etkilenir
Changed (C)   — Diğer bileşenler de etkilenir
```

### Confidentiality/Integrity/Availability Impact (C/I/A)
```
None (N) — Etki yok
Low (L)  — Kısmi etki
High (H) — Tam etki
```

### Yaygın Senaryolar ve CVSS Skorları
```
RCE (unauthenticated)     → AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  = 10.0 Critical
SQL Injection (data leak) → AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  = 9.1 Critical
Stored XSS                → AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N  = 5.4 Medium
SSRF (internal access)    → AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N  = 8.6 High
IDOR                      → AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  = 6.5 Medium
Open Redirect             → AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  = 6.1 Medium
CSRF                      → AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N  = 4.3 Medium
Info Disclosure           → AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  = 5.3 Medium
```

## Zafiyet Tipine Göre Rapor Şablonları

### SQL Injection Raporu
```markdown
## SQL Injection in [Endpoint]

**Severity:** Critical (CVSS 9.8)
**CWE:** CWE-89 (Improper Neutralization of Special Elements in SQL Commands)

### Açıklama
[Endpoint] üzerinde kullanıcı girdisi SQL sorgusuna doğrudan dahil ediliyor. 
`[parameter]` parametresi sanitize edilmeden SQL sorgusunda kullanılıyor.

### PoC
\`\`\`bash
# Veritabanı tespiti
sqlmap -u "URL" -p "param" --batch --dbs

# Tablo listesi
sqlmap -u "URL" -p "param" --batch -D dbname --tables

# Veri çıkarma
sqlmap -u "URL" -p "param" --batch -D dbname -T users --dump
\`\`\`

### Etki
- Tüm veritabanı verilerine erişim
- Kullanıcı credential'larının sızdırılması
- Potansiyel olarak OS komut çalıştırma (--os-shell)

### Düzeltme
1. Prepared statements / parameterized queries kullan
2. ORM kullan
3. Input validation ve whitelist filtering uygula
4. Veritabanı kullanıcı yetkilerini minimize et
5. WAF kuralları ekle
```

### XSS Raporu
```markdown
## [Stored/Reflected/DOM] XSS in [Location]

**Severity:** [High/Medium] (CVSS X.X)
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)

### Açıklama
[Location] üzerinde kullanıcı girdisi HTML/JavaScript bağlamında 
escape edilmeden render ediliyor.

### PoC
Payload: `<script>alert(document.domain)</script>`
veya: `<img src=x onerror=alert(document.domain)>`

### Etki
- Session hijacking (cookie theft)
- Account takeover
- Phishing
- Keylogging
- Defacement

### Düzeltme
1. Context-aware output encoding (HTML, JS, URL, CSS)
2. Content Security Policy (CSP) header ekle
3. HTTPOnly ve Secure cookie flag'leri
4. Input validation (whitelist)
5. DOMPurify kütüphanesi kullan (DOM XSS için)
```

### SSRF Raporu
```markdown
## SSRF in [Feature]

**Severity:** High (CVSS 8.6)
**CWE:** CWE-918 (Server-Side Request Forgery)

### Açıklama
[Feature] kullanıcının verdiği URL'ye sunucu tarafından istek yapıyor.
Bu, dahili ağdaki servislere ve cloud metadata endpoint'lerine erişim sağlıyor.

### PoC
\`\`\`bash
# AWS Metadata erişimi
curl -X POST URL -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
\`\`\`

### Etki
- Dahili ağ keşfi ve tarama
- Cloud credential'ları sızdırma (AWS IAM, GCP SA)
- Dahili servislere erişim (Redis, Elasticsearch, vs.)
- Port scanning

### Düzeltme
1. URL whitelist uygula
2. Dahili IP aralıklarını blacklist'e al (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
3. DNS resolution sonrası IP kontrolü yap
4. Egress firewall kuralları
5. Cloud metadata'ya erişimi kısıtla (IMDSv2)
```

## Düzeltme Önerileri — Hızlı Referans

| Zafiyet | Birincil Düzeltme |
|---------|-------------------|
| SQLi | Prepared statements |
| XSS | Output encoding + CSP |
| SSRF | URL whitelist + IP blacklist |
| CSRF | CSRF token + SameSite cookie |
| IDOR | Server-side authorization check |
| LFI/RFI | Input whitelist + chroot |
| Command Injection | Avoid shell exec + input validation |
| SSTI | Sandboxed template engine + input escape |
| XXE | Disable DTD processing |
| Deserialization | Whitelist allowed classes |
| File Upload | Whitelist extensions + content validation |
| Auth Bypass | Proper session management + MFA |
| Open Redirect | URL whitelist |
| CORS | Strict origin validation |

## Pentest Rapor Yapısı — Executive Summary

```markdown
# Penetrasyon Testi Raporu — [Hedef]

**Tarih:** [Tarih]
**Test Tipi:** [Web App / Network / Mobile / API]
**Scope:** [Scope tanımı]
**Metodoloji:** OWASP Testing Guide / PTES / OSSTMM

## Yönetici Özeti
[Genel durum değerlendirmesi — 2-3 paragraf]
[Testin kapsamı ve süresi]
[Kritik bulgular özeti]

## Risk Özeti
| Severity | Sayı |
|----------|------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Informational | X |

## Kritik Bulgular
[En önemli 3-5 bulgu hızlı özet]

## Detaylı Bulgular
[Her bulgu için tam rapor]

## Genel Öneriler
[Stratejik güvenlik önerileri]
```
