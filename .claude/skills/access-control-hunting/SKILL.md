---
name: access-control-hunting
description: "Erişim kontrolü ve iş mantığı bug avcılığı skill'i — bug bounty'de EN ÇOK ÖDEYEN sınıflar (OWASP #1 Broken Access Control + OWASP API #1/#5). Bu skill'i şu durumlarda kullan: kullanıcı 'broken access control', 'access control', 'BOLA', 'BFLA', 'IDOR', 'authorization', 'yetki', 'horizontal/vertical privilege escalation', 'privilege escalation', 'mass assignment', 'business logic', 'iş mantığı', 'price manipulation', 'fiyat', 'race condition', 'coupon', 'workflow bypass', 'OWASP API', 'multi-tenant' dediğinde; veya bir API/uygulamada yetki sınırlarını, kullanıcı izolasyonunu, ödeme/sepet/abonelik iş mantığını test etmek istediğinde. mcp-hunter zekasını (predict_vulnerabilities, build_authz_matrix, analyze_authz_result, generate_abuse_cases, hunt_variants, coverage_report) bu sınıflara yönlendirir. Otomatik tarayıcıların KAÇIRDIĞI, akıl yürütme gerektiren bug'lar burada."
---

# 🎯 Erişim Kontrolü & İş Mantığı Bug Avcılığı

> **İlke:** *"Tarayıcılar enjeksiyon bulur; gerçek para erişim kontrolü ve iş mantığında.
> Bunlar imza ile değil, AKIL YÜRÜTME ile bulunur — bu yüzden AI burada tarayıcıyı ezer."*

OWASP Web Top 10 #1 = **Broken Access Control**. OWASP API Top 10 #1 = **BOLA**, #5 = **BFLA**.
Bug bounty ödemelerinin büyük kısmı bu sınıflardan gelir. Bu skill `mcp-hunter` biliş
katmanını bu sınıflara yönlendirir.

## 🧠 mcp-hunter Tool Akışı (ZORUNLU sıra)

```
1) PREDICT  → mcp__hunter__predict_vulnerabilities(target, fingerprint, context)
   → stack'e özel hangi sınıflar muhtemel + CVE ailesi + hangi skill/validator
2) COVERAGE → mcp__hunter__coverage_report(target)
   → hangi (endpoint × sınıf) test edilmedi? 'access_control'/'business_logic' kör noktası var mı?
3) ACCESS CONTROL (en yüksek ödül):
   a. mcp__hunter__build_authz_matrix(target, identities, resources, object_ids)
      → anon/userA/userB/admin × kaynaklar farksal test matrisi (BOLA/BFLA/unauth)
   b. Her testi ÇALIŞTIR (curl/web-advanced) → iki kimliğin yanıtını topla
   c. mcp__hunter__analyze_authz_result(test_json)
      → owner vs attacker farksal ORACLE → CONFIRMED ise KANIT (LLM görüşü değil)
4) BUSINESS LOGIC:
   mcp__hunter__generate_abuse_cases(target, endpoint, params, context)
   → fiyat/miktar/rol/kupon/iş-akışı/race kötüye-kullanım senaryoları
5) ÇOĞALT:
   mcp__hunter__hunt_variants(finding_type, target, param, endpoint)
   → doğrulanan bug'ı kardeş param/endpoint/method/subdomain'de sistematik ara
6) KAYDET + ÖĞREN:
   mcp__memory-server__store_finding + mcp__reasoning__record_lesson(worked=?)
   + mcp__reasoning__exploitability_score → mcp__hunter__coverage_report (tekrar; % arttı mı?)
```

## 1️⃣ BOLA / IDOR (Object-Level Authorization)

**Tanım:** Bir kullanıcı, başka kullanıcının objesine (id/uuid) erişebiliyor.

**Test:**
- `userA` ile bir obje oluştur/eriş → id'yi not et (owner yanıtı = KONTROL).
- `userB` token'ı ile AYNI id'ye eriş.
- **Kanıt (analyze_authz_result):** `userB` 2xx + owner yanıtıyla **byte-aynı** (hash) veya
  owner'a özgü işaretçileri (e-posta/isim) içeriyorsa → **BOLA KANITLANDI**.

**İpuçları:** Sıralı id → enumeration; UUID → leak kaynağı ara (eski yanıt, log, referer);
sayısal olmayan id'leri tahmin/dahil et; toplu (bulk) endpoint'lerde filtre atla.

## 2️⃣ BFLA (Function-Level Authorization)

**Tanım:** Düşük yetkili kullanıcı, ayrıcalıklı fonksiyonu çağırabiliyor.

**Test:**
- `admin`, `/admin/...`, `/manage`, `delete`, `approve`, `export` gibi fonksiyonları kullanır.
- `userB` token'ı ile aynı endpoint'i çağır — ve **method'ları değiştir** (GET→POST/PUT/DELETE,
  `X-HTTP-Method-Override`).
- **Kanıt:** düşük yetkili 2xx + işlem gerçekleşti → **BFLA**.

## 3️⃣ Unauth Access

Anon (token YOK) korunan kaynağa eriş → 2xx dönerse kimlik doğrulama atlanmış.
`/api/v1/...` çoğu zaman bazı endpoint'lerde auth unutur.

## 4️⃣ Mass Assignment / Privilege Escalation

GET yanıtındaki TÜM alanları (özellikle `is_admin`, `role`, `balance`, `verified`,
`owner_id`, `plan`) create/update **gövdesine geri yaz** → gizli ayrıcalıklı alanı set et.
JSON ↔ form ↔ nested (`user[role]=admin`) varyasyonları dene.

## 5️⃣ İş Mantığı (Business Logic)

`generate_abuse_cases` ile parametre semantiğine göre:
- **price/amount/total:** negatif, sıfır, ondalık, istemci-taraflı fiyat güveni, overflow.
- **quantity/qty:** negatif (iade istismarı), 0, aşırı büyük, ondalık.
- **coupon/promo:** replay, stacking, brute, self-referral.
- **step/state/status:** adım atlama, durum zorlama (`status=paid`), geri sarma.
- **otp/code:** brute (rate-limit yok), replay, response manipülasyonu, null bypass.

## 6️⃣ Race Condition (ToCToU)

Tekil-kullanım kaynaklarda (kupon, bakiye, stok, para çekme, oy) **N paralel istek**
gönder → çift kullanım/double-spend. `curl ... &` ile 20 paralel veya Turbo Intruder
"single packet attack". Sayaç 1 yerine N düştüyse → bug.

## ⚠️ Doğrulama & OPSEC

- **Her erişim kontrolü iddiası `analyze_authz_result` farksal oracle'ı ile KANITLANMALI**
  (owner=KONTROL, attacker=TEST). False-positive guard budur.
- **Yıkıcı testler** (silme/transfer/onay) → önce scope/onay; mümkünse **idempotent** veya
  geri-alınabilir kaynakta dene; `mcp__kali-tools__request_approval`.
- Bulgu kanıtı: iki kimliğin tam HTTP istek/yanıtı (header dahil) + farksal açıklama.
- CONFIRMED → `store_finding(severity='high'/'critical')` + `exploitability_score` +
  `hunt_variants` ile çoğalt + `/report-generator`.

## 🎖️ Neden bu skill kritik?

| Sınıf | OWASP | Tarayıcı bulur mu? | Bug bounty ödülü |
|-------|-------|--------------------|------------------|
| BOLA/IDOR | API #1 | ❌ (yetki bağlamı yok) | 💰💰💰 |
| BFLA | API #5 | ❌ | 💰💰💰 |
| Mass Assignment | API #3 | ⚠️ kısmen | 💰💰 |
| İş mantığı | — | ❌ (akıl yürütme) | 💰💰💰 |
| Race condition | — | ❌ | 💰💰 |

> mcp-hunter bu sınıfları DETERMİNİSTİK matris + farksal oracle'a indirger → AI'nın
> "yaratıcı keşfi" + "mantıksal kanıtı" birleşir. Tek bug değil, `hunt_variants` ile sürü.
