# 🕸️ Modern Web + API Workflow

Modern web uygulamaları (SPA, API-first) ve OAuth/SAML/GraphQL gibi kompleks
auth sistemleri için adım adım pentest pipeline'ı.

## 📋 Önkoşullar

- `web-advanced` MCP server aktif (config.yaml → mcp_servers.web-advanced.enabled: true)
- Hedef scope'a eklenmiş (`/scope add target.com`)
- Bug bounty programının Terms of Service'i okundu

## 🎯 Faz 1 — Keşif & Teknoloji Tespiti

```
1. Subfinder + amass ile subdomain listesi
2. httpx ile canlı host'lar + teknolojiler (whatweb kombosu)
3. Her host için:
   a. Swagger/OpenAPI path'leri dene: /swagger, /api-docs, /openapi.json
   b. GraphQL endpoint kontrol: /graphql, /api/graphql, /v1/graphql
   c. WebSocket detection: Connection: Upgrade response header
4. Teknoloji → skill seç:
   - JWT token gözlem → 🔐 JWT fazı
   - /graphql bulundu → 🔵 GraphQL fazı
   - /api/oauth gözüktü → 🌐 OAuth fazı
```

## 🎯 Faz 2 — API Schema Discovery

```
# OpenAPI spec varsa
openapi_ingest(source="https://api.target.com/openapi.json")
   → endpoint + param + security tag listesi
   → tehlikeli path'leri işaretler (admin, delete, internal)

# Postman collection varsa (GitHub leak, wayback vb.)
postman_ingest(collection_path="/tmp/target.postman_collection.json")

# Shadow endpoint discovery (spec'te olmayan)
api_route_fuzz(base_url="https://api.target.com", threads=20)
   → .git/config, .env, actuator/health, debug, console gibi internal endpoint'ler

# Gizli parametre keşfi
api_param_discover(url="https://api.target.com/users", method="GET")
   → debug, admin, role, bypass gibi yanıtı değiştiren param'lar
```

## 🎯 Faz 3 — Authentication Testleri

### 3A. JWT varsa
```
jwt_analyze(token="eyJ...")
   → alg, claims, zaafiyet gözlemleri

# HS256 ise secret brute
if alg == "HS256":
    jwt_brute_hs256(token=..., wordlist="/usr/share/wordlists/jwt-secrets.txt")

# alg=none deneme
jwt_attack_alg_none(token=..., claims_override='{"role":"admin","isAdmin":true}')
   → 8 varyant → hepsini test et

# RS256 ise
if alg.startswith("RS"):
    # Public key'i /.well-known/jwks.json veya x5u URL'inden al
    jwt_rs_to_hs_confusion(token=..., public_key_pem="-----BEGIN PUBLIC KEY-----\n...")
```

### 3B. OAuth varsa
```
# Authorize endpoint keşfedilecek (örn: /oauth/authorize)
oauth_redirect_bypass(
    auth_url="https://target.com/oauth/authorize",
    client_id="client_abc",
    legit_callback="https://app.target.com/cb",
    attacker="https://hackeragent.local/cb"
)
   → 15 varyant → attacker server'ında hit gelen varyant = bypass
```

### 3C. SAML varsa
```
# SAML response'ı yakala (Burp'le)
saml_xsw_variants(saml_b64="PHN1YmplY3Q...")
   → XSW1-XSW8 saldırı rehberi
   → Her varyantı manuel Burp SAMLRaider ile oluştur+gönder
```

### 3D. NoSQLi (login bypass)
```
nosqli_mongo_test(
    url="https://api.target.com/login",
    param="username",
    method="POST",
    body_template='{"username":"admin","password":"x"}'
)
   → $ne, $gt, $regex, $where denemeleri
   → TIME-BASED işareti = $where code execution
```

## 🎯 Faz 4 — GraphQL Testleri (varsa)

```
graphql_introspect(url="https://target.com/graphql")
   → Açıksa tüm schema
   → Kapalıysa:

graphql_suggestion_scan(url="https://target.com/graphql")
   → "Did you mean..." ile field enumeration

# Login mutation bulduysan → batch attack (rate limit bypass)
graphql_batch_attack(
    url="...",
    query='login(email:"admin@target.com", password:"CANDIDATE") { token }',
    batch_size=50
)
   → Tek HTTP req'de 50 login denemesi
```

## 🎯 Faz 5 — Authorization (IDOR + Privilege Escalation)

```
# İki farklı user ile giriş yap, token'ları topla
# Kendi ID'n ve başka user ID'si

api_idor_matrix(
    url_template="https://api.target.com/users/{ID}/private",
    ids="42,43,1,9999",  # 42=self, 43=other, 1=admin, 9999=non-existent
    tokens="eyJ...user42Token,eyJ...user43Token"
)
   → Matrix: token × ID → 200'se yetki ihlali
```

## 🎯 Faz 6 — Header-Based Bypass'lar

```
# Rate limit bypass
api_rate_bypass_probe(url="https://api.target.com/login", count=30)
   → Hangi header IP spoofing'i geçiyor?

# Cache poisoning
cache_poisoning_probe(url="https://target.com/")
   → Unkeyed X-Forwarded-Host reflection = XSS/redirect
```

## 🎯 Faz 7 — Advanced HTTP

```
# HTTP Smuggling
http_smuggling_probe(url="https://target.com/login")
   → Timing anomalisi = CL.TE veya TE.CL ihtimali
   → Manuel smuggler.py veya Burp Smuggler ile doğrula

# WebSocket CSWSH
websocket_handshake_test(
    ws_url="wss://target.com/ws",
    origin="https://evil.com"
)
   → 101 → cross-origin WS kabul = hesap hijack
```

## 🎯 Faz 8 — Client-Side + Data Exfil

```
# Prototype Pollution
prototype_pollution_scan(url="https://target.com/search?q=test")

# Race condition (double spend, coupon reuse)
race_condition_test(
    url="https://api.target.com/apply-coupon",
    method="POST",
    body='{"code":"DISCOUNT50"}',
    headers='{"Authorization":"Bearer ..."}',
    count=30
)
   → Farklı status code'lar → race mümkün

# Formula injection (CSV export varsa)
formula_injection_payloads(scenario="rce")
   → Payload'ları export edilen alana gir (name, comment, vb.)
```

## 🎯 Faz 9 — Bulguları Kaydet ve Raporla

```
# Her bulgu için:
memory-server.store_finding(
    target="target.com",
    category="auth_bypass",  # veya idor, cache_poisoning, smuggling vb.
    severity="critical",     # critical/high/medium/low
    title="JWT HS256 weak secret",
    description="...",
    poc="..."
)

# Notifier varsa kritik bulgu otomatik push
# (config.yaml → notifications.enabled: true)

# Tüm finding'ler için rapor
report-generator.generate_hackerone_report(target="target.com")
```

## 📊 Başarı Kriterleri

- [ ] Tüm endpoint'ler haritalandı (spec + fuzz)
- [ ] Authentication vektörleri test edildi (JWT/OAuth/SAML/NoSQL)
- [ ] Authorization matrisi çalıştırıldı (IDOR)
- [ ] Header-based bypass testleri yapıldı (rate limit, cache)
- [ ] Client-side zafiyetler tarandı (PP, race)
- [ ] Her finding memory-server'a kaydedildi
- [ ] HackerOne/Bugcrowd formatında rapor üretildi

## ⚠️ OPSEC Notları

1. **Rate limit**: `set_rate_limit(5)` ile başla (bug bounty mantığı)
2. **Scope**: `/scope list` ile her tool öncesi kontrol et
3. **Batch sizing**: `graphql_batch_attack(batch_size=50)` — 500+ server crash
4. **Race testing**: Üretim/checkout endpoint'lerinde dikkat (gerçek işlem tetiklenir)
5. **Smuggling**: Test sonrası cache'e zarar verilebilir — incident response hazır ol
