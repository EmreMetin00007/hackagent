# 🎯 Bug Bounty İş Akışı

Bu doküman HackerAgent orkestratörünün bir bug bounty hedefinde takip edeceği tam iş akışını tanımlar.

## Faz 1: Hedef Algılama ve Scope Belirleme
```
INPUT: Hedef domain/IP/program
│
├── Bug bounty programının scope'unu oku
├── In-scope varlıkları listele
├── Out-of-scope varlıkları not et
├── Kuralları ve kısıtlamaları anla
└── Çalışma dizini oluştur: target-name/
```

## Faz 2: Pasif Keşif
```
├── WHOIS + DNS tam sorgu
├── Subdomain enumeration (subfinder, amass, crt.sh)
├── Alive subdomain tespiti (httpx)
├── Teknoloji fingerprinting (whatweb)
├── Google/GitHub dork'ları
├── Shodan/Censys sorguları
├── Wayback Machine URL toplama
├── Cloud asset keşfi (S3, Azure blob)
├── SSL sertifika analizi
└── Tüm sonuçları recon/ dizinine kaydet
```

## Faz 3: Aktif Keşif
```
├── Port tarama (nmap: quick → full → detailed)
├── Servis versyon tespiti
├── OS fingerprinting
├── WAF tespiti (wafw00f)
├── Dizin ve dosya brute-force (ffuf/gobuster)
├── VHost keşfi
├── Parameter keşfi (arjun)
├── API endpoint keşfi
├── JavaScript analizi (linkfinder)
├── CMS tespiti ve tarama
└── Sonuçları enum/ dizinine kaydet
```

## Faz 4: Zafiyet Keşfi
```
├── HER input noktasını test et:
│   ├── SQL Injection (manual + sqlmap)
│   ├── XSS (reflected, stored, DOM)
│   ├── SSRF (internal access, cloud metadata)
│   ├── LFI/RFI (path traversal, PHP wrappers)
│   ├── Command Injection
│   ├── SSTI (template engine detection + exploit)
│   ├── XXE (XML endpoint varsa)
│   ├── Insecure Deserialization
│   ├── File Upload Bypass
│   ├── IDOR (ID değiştirerek erişim)
│   ├── Authentication flaws (JWT, session, OAuth)
│   ├── Authorization flaws (privilege escalation)
│   ├── Business logic bugs
│   ├── Race conditions
│   ├── CORS misconfiguration
│   ├── HTTP Request Smuggling
│   ├── Web Cache Poisoning
│   ├── GraphQL abuse
│   ├── NoSQL Injection
│   ├── Subdomain takeover
│   └── Open Redirect
├── Otomatik tarayıcı çalıştır (nuclei)
├── Nikto web server taraması
└── Bulguları vulns/ dizinine kaydet
```

## Faz 5: Exploitation & PoC
```
├── Her zafiyet için PoC oluştur
├── CVSS skorunu hesapla
├── Impact'i belirle
├── Screenshot/video kanıt topla
├── Reproducible steps yaz
├── Exploit'i temiz bir şekilde belgele
└── Exploit'leri exploits/ dizinine kaydet
```

## Faz 6: Raporlama
```
├── report-generator skill'ini kullan
├── Her bulgu için HackerOne formatında rapor yaz
├── CVSS vektörü ekle
├── PoC ve evidence ekle
├── Remediation önerileri yaz
├── Raporları gözden geçir
└── Submit et
```

## Sürekli Döngü
```
Her fazdan sonra:
├── Yeni keşifler yeni saldırı yüzeyleri açar mı? → EVET → İlgili faza dön
├── Exploit sonucu yeni erişim sağladı mı? → EVET → Post-exploitation yap
└── Tüm vektörler tükendi mi? → EVET → Raporla ve bitir
```

## Öncelik Sırası (Ödül Optimizasyonu)
```
1. 🔴 Critical: RCE, Auth Bypass, SQLi (data access), SSRF (cloud creds)
2. 🟠 High: Stored XSS (admin), IDOR (sensitive data), File Upload RCE
3. 🟡 Medium: Reflected XSS, CSRF, Open Redirect, Info Disclosure
4. 🟢 Low: Self-XSS, CORS, missing headers, verbose errors
```
