---
name: web-advanced
description: "Modern web ve API saldırı skill'i. GraphQL injection, JWT attacks, OAuth/OIDC/SAML misconfiguration, HTTP Request Smuggling (CL.TE/TE.CL/TE.TE), Web Cache Poisoning, Prototype Pollution, Race Condition/TOCTOU, WebSocket fuzzing, NoSQL Injection, IDOR matrix, Rate Limiting bypass, Formula Injection, API route fuzzing, OpenAPI/Postman ingest. Bu skill'i şu durumlarda kullan: kullanıcı 'GraphQL', 'JWT', 'OAuth', 'SAML', 'OIDC', 'smuggling', 'cache poisoning', 'prototype pollution', 'race condition', 'WebSocket', 'NoSQL', 'IDOR', 'rate limit bypass', 'API test', 'OpenAPI', 'Postman', 'formula injection', 'modern SPA', 'React/Vue/Angular' dediğinde veya modern bir web/API uygulamasının güvenlik testi istendiğinde. Özellikle klasik `kali-tools`'un yetmediği API-first uygulamalarında mutlaka bu skill'i kullan — `web-advanced` MCP server'ı üzerinden 23 özel tool çağır."
---

# 🕸️ Modern Web + API Saldırı Skill'i

Modern web / API odaklı bug bounty avı için `web-advanced` MCP server'ını
kullanır. 23 yeni tool, klasik `kali-tools`'un kapsam dışı bıraktığı
alanları kapsar.

## 🧠 Ne Zaman Kullan

- Hedef modern bir SPA / API-first uygulama ise (React/Vue/Angular + REST/GraphQL)
- Authentication akışı (JWT, OAuth, SAML, OIDC) test edilecekse
- Swagger/OpenAPI/Postman collection paylaşılmışsa → hızlı endpoint ingest
- Klasik sqlmap/nuclei zaten çalıştırıldıysa bir sonraki katmana geçmek için

## 🔧 Tool Kategorileri

### 🔵 GraphQL
- `graphql_introspect` — schema introspection (açıksa tüm type+query listesi)
- `graphql_suggestion_scan` — introspection kapalıyken "Did you mean..." üzerinden enumeration
- `graphql_batch_attack` — alias overload (rate limit bypass, brute force)

### 🔐 JWT
- `jwt_analyze` — decode + güvenlik gözlemleri (alg, kid, jku, jwk, yetki claim'leri)
- `jwt_attack_alg_none` — 8 varyant alg:none token üretir
- `jwt_brute_hs256` — HS256/384/512 secret brute (built-in weak list + custom wordlist)
- `jwt_rs_to_hs_confusion` — RS→HS algorithm confusion (public key secret olarak)

### 🌐 OAuth / SAML
- `oauth_redirect_bypass` — 15 redirect_uri bypass varyantı
- `saml_xsw_variants` — XSW1-XSW8 manuel saldırı rehberi

### 🚇 HTTP Request Smuggling
- `http_smuggling_probe` — CL.TE / TE.CL / TE.TE timing-based detection (raw socket)

### 💾 Cache & CORS
- `cache_poisoning_probe` — unkeyed header detection (X-Forwarded-Host vb.)
- `cors_advanced_scan` — 9 origin bypass senaryosu

### 🧬 Prototype Pollution & Race
- `prototype_pollution_scan` — query string tabanlı PP heuristikleri
- `race_condition_test` — threading.Barrier ile eşzamanlı N istek (TOCTOU, double-spend)

### 🔌 WebSocket
- `websocket_handshake_test` — Origin check + CSWSH tespiti

### 📘 OpenAPI / Postman Ingest (Paket 2)
- `openapi_ingest` — Swagger/OpenAPI YAML/JSON → endpoint+param listesi (tehlikeli path'leri işaretler)
- `postman_ingest` — Postman v2 collection → endpoint extraction

### 🎯 API Discovery
- `api_route_fuzz` — built-in ~65 route + custom wordlist bruteforce
- `api_param_discover` — Arjun-style hidden parameter finder (yanıt size/status diff)

### 💉 NoSQLi
- `nosqli_mongo_test` — MongoDB operator injection ($ne, $gt, $regex, $where RCE)

### 🆔 IDOR & Rate Bypass
- `api_idor_matrix` — multi-token × multi-ID matrisi (yetkili/yetkisiz erişim tespiti)
- `api_rate_bypass_probe` — 9 varyant (IP spoofing header'ları + path obfuscation)

### 📄 Formula Injection
- `formula_injection_payloads` — CSV/Excel formula (cmd|calc, HYPERLINK exfil, WEBSERVICE)

## 🎯 Tipik Saldırı Akışı

```
1. Target keşfedildi: SPA + REST API (api.target.com)
2. openapi_ingest("https://api.target.com/v1/openapi.json")
   → endpoint listesi + tehlikeli path'ler (admin, delete, upload)
3. api_route_fuzz("https://api.target.com") 
   → spec'te olmayan shadow endpoint'leri bul (debug, .git, backup)
4. Login endpoint bulundu → nosqli_mongo_test ile auth bypass dene
5. Token alındı → jwt_analyze → weak HS256 şüphesi → jwt_brute_hs256
6. Secret kırıldı → role=admin claim ile forge
7. Admin token ile api_idor_matrix (kendi + başka user ID'ler)
8. Bulgu: /api/users/{ID} tüm token'larla 200 → IDOR
9. memory-server.store_finding(severity="critical", ...)
10. report-generator ile HackerOne formatında rapor
```

## ⚠️ OPSEC

- `graphql_batch_attack` server crash yapabilir (batch_size > 500 dikkat)
- `race_condition_test` 30+ paralel istek rate limiter'ı tetikler
- `http_smuggling_probe` yan etkisi olabilir (gerçek istek enjekte eder)
- `formula_injection_payloads` SADECE payload üretir — test sahibinin 
  onayladığı input alanlarında kullan

## 📚 İlgili Workflow

- `workflows/modern-web-workflow.md` — adım adım modern web pipeline
